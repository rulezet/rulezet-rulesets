rule TTP_XOR_WriteProcessMemory_efd5 {
  strings:
    $key_efd5 = { b8 a7 [2] 8a 85 [2] 8c b0 [2] a2 b0 [2] 9d ac }

  condition:
    any of them
}