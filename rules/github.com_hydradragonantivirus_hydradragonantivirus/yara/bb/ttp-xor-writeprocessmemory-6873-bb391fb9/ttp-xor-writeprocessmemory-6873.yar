rule TTP_XOR_WriteProcessMemory_6873 {
  strings:
    $key_6873 = { 3f 01 [2] 0d 23 [2] 0b 16 [2] 25 16 [2] 1a 0a }

  condition:
    any of them
}