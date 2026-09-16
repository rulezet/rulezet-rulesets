rule TTP_XOR_WriteProcessMemory_2757 {
  strings:
    $key_2757 = { 70 25 [2] 42 07 [2] 44 32 [2] 6a 32 [2] 55 2e }

  condition:
    any of them
}