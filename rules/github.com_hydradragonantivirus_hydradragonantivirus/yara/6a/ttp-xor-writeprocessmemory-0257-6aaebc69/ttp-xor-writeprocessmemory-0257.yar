rule TTP_XOR_WriteProcessMemory_0257 {
  strings:
    $key_0257 = { 55 25 [2] 67 07 [2] 61 32 [2] 4f 32 [2] 70 2e }

  condition:
    any of them
}