rule TTP_XOR_WriteProcessMemory_2157 {
  strings:
    $key_2157 = { 76 25 [2] 44 07 [2] 42 32 [2] 6c 32 [2] 53 2e }

  condition:
    any of them
}