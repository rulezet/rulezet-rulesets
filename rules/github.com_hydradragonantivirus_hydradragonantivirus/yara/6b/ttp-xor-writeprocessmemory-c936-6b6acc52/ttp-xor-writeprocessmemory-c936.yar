rule TTP_XOR_WriteProcessMemory_c936 {
  strings:
    $key_c936 = { 9e 44 [2] ac 66 [2] aa 53 [2] 84 53 [2] bb 4f }

  condition:
    any of them
}