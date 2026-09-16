rule TTP_XOR_WriteProcessMemory_4061 {
  strings:
    $key_4061 = { 17 13 [2] 25 31 [2] 23 04 [2] 0d 04 [2] 32 18 }

  condition:
    any of them
}