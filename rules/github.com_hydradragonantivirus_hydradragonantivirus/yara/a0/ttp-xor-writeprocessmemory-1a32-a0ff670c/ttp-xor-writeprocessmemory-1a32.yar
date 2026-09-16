rule TTP_XOR_WriteProcessMemory_1a32 {
  strings:
    $key_1a32 = { 4d 40 [2] 7f 62 [2] 79 57 [2] 57 57 [2] 68 4b }

  condition:
    any of them
}