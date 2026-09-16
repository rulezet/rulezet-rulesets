rule TTP_XOR_WriteProcessMemory_1f89 {
  strings:
    $key_1f89 = { 48 fb [2] 7a d9 [2] 7c ec [2] 52 ec [2] 6d f0 }

  condition:
    any of them
}