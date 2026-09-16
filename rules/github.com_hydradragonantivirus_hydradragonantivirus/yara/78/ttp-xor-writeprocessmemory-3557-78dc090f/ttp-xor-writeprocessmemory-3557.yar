rule TTP_XOR_WriteProcessMemory_3557 {
  strings:
    $key_3557 = { 62 25 [2] 50 07 [2] 56 32 [2] 78 32 [2] 47 2e }

  condition:
    any of them
}