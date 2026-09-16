rule TTP_XOR_WriteProcessMemory_5a73 {
  strings:
    $key_5a73 = { 0d 01 [2] 3f 23 [2] 39 16 [2] 17 16 [2] 28 0a }

  condition:
    any of them
}