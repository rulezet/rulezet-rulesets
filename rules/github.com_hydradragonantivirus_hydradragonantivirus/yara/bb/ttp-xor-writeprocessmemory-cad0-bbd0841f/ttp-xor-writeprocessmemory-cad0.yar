rule TTP_XOR_WriteProcessMemory_cad0 {
  strings:
    $key_cad0 = { 9d a2 [2] af 80 [2] a9 b5 [2] 87 b5 [2] b8 a9 }

  condition:
    any of them
}