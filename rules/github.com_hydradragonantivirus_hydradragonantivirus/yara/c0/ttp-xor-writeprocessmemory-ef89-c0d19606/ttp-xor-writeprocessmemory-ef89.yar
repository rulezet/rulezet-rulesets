rule TTP_XOR_WriteProcessMemory_ef89 {
  strings:
    $key_ef89 = { b8 fb [2] 8a d9 [2] 8c ec [2] a2 ec [2] 9d f0 }

  condition:
    any of them
}