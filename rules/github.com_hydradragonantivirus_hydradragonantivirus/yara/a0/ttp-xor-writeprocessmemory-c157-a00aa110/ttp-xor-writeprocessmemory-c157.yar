rule TTP_XOR_WriteProcessMemory_c157 {
  strings:
    $key_c157 = { 96 25 [2] a4 07 [2] a2 32 [2] 8c 32 [2] b3 2e }

  condition:
    any of them
}