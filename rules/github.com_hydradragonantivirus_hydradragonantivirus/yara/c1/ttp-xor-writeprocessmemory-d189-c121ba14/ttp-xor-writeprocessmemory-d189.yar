rule TTP_XOR_WriteProcessMemory_d189 {
  strings:
    $key_d189 = { 86 fb [2] b4 d9 [2] b2 ec [2] 9c ec [2] a3 f0 }

  condition:
    any of them
}