rule TTP_XOR_WriteProcessMemory_3f73 {
  strings:
    $key_3f73 = { 68 01 [2] 5a 23 [2] 5c 16 [2] 72 16 [2] 4d 0a }

  condition:
    any of them
}