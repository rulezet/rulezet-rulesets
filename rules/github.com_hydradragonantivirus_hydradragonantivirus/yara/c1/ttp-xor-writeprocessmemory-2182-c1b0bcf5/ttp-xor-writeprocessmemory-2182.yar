rule TTP_XOR_WriteProcessMemory_2182 {
  strings:
    $key_2182 = { 76 f0 [2] 44 d2 [2] 42 e7 [2] 6c e7 [2] 53 fb }

  condition:
    any of them
}