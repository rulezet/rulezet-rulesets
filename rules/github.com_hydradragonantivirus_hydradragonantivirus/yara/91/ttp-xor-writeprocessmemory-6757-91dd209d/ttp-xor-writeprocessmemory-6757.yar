rule TTP_XOR_WriteProcessMemory_6757 {
  strings:
    $key_6757 = { 30 25 [2] 02 07 [2] 04 32 [2] 2a 32 [2] 15 2e }

  condition:
    any of them
}