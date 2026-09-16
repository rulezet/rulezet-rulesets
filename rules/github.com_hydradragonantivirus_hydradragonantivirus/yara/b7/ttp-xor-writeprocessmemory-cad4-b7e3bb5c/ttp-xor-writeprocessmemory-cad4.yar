rule TTP_XOR_WriteProcessMemory_cad4 {
  strings:
    $key_cad4 = { 9d a6 [2] af 84 [2] a9 b1 [2] 87 b1 [2] b8 ad }

  condition:
    any of them
}