rule TTP_XOR_WriteProcessMemory_4a32 {
  strings:
    $key_4a32 = { 1d 40 [2] 2f 62 [2] 29 57 [2] 07 57 [2] 38 4b }

  condition:
    any of them
}