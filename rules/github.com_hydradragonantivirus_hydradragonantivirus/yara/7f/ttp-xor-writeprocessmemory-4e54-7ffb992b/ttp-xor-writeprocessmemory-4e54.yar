rule TTP_XOR_WriteProcessMemory_4e54 {
  strings:
    $key_4e54 = { 19 26 [2] 2b 04 [2] 2d 31 [2] 03 31 [2] 3c 2d }

  condition:
    any of them
}