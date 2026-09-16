rule TTP_XOR_WriteProcessMemory_1a74 {
  strings:
    $key_1a74 = { 4d 06 [2] 7f 24 [2] 79 11 [2] 57 11 [2] 68 0d }

  condition:
    any of them
}