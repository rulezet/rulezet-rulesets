rule TTP_XOR_WriteProcessMemory_3e54 {
  strings:
    $key_3e54 = { 69 26 [2] 5b 04 [2] 5d 31 [2] 73 31 [2] 4c 2d }

  condition:
    any of them
}