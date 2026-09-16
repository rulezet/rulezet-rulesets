rule TTP_XOR_WriteProcessMemory_e2d5 {
  strings:
    $key_e2d5 = { b5 a7 [2] 87 85 [2] 81 b0 [2] af b0 [2] 90 ac }

  condition:
    any of them
}