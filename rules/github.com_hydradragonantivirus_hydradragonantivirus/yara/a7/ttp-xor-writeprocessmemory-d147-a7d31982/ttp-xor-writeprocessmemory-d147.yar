rule TTP_XOR_WriteProcessMemory_d147 {
  strings:
    $key_d147 = { 86 35 [2] b4 17 [2] b2 22 [2] 9c 22 [2] a3 3e }

  condition:
    any of them
}