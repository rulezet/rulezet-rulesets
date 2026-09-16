rule TTP_XOR_WriteProcessMemory_cad1 {
  strings:
    $key_cad1 = { 9d a3 [2] af 81 [2] a9 b4 [2] 87 b4 [2] b8 a8 }

  condition:
    any of them
}