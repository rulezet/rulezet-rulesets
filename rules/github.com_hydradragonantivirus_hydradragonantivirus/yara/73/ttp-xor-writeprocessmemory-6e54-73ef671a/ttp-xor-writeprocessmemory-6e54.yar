rule TTP_XOR_WriteProcessMemory_6e54 {
  strings:
    $key_6e54 = { 39 26 [2] 0b 04 [2] 0d 31 [2] 23 31 [2] 1c 2d }

  condition:
    any of them
}