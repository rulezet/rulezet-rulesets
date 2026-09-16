rule TTP_XOR_WriteProcessMemory_d690 {
  strings:
    $key_d690 = { 81 e2 [2] b3 c0 [2] b5 f5 [2] 9b f5 [2] a4 e9 }

  condition:
    any of them
}