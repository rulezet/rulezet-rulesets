rule TTP_XOR_WriteProcessMemory_6517 {
  strings:
    $key_6517 = { 32 65 [2] 00 47 [2] 06 72 [2] 28 72 [2] 17 6e }

  condition:
    any of them
}