rule TTP_XOR_WriteProcessMemory_5557 {
  strings:
    $key_5557 = { 02 25 [2] 30 07 [2] 36 32 [2] 18 32 [2] 27 2e }

  condition:
    any of them
}