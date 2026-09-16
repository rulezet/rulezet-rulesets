rule TTP_XOR_WriteProcessMemory_cad5 {
  strings:
    $key_cad5 = { 9d a7 [2] af 85 [2] a9 b0 [2] 87 b0 [2] b8 ac }

  condition:
    any of them
}