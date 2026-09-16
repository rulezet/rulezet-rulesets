rule TTP_XOR_WriteProcessMemory_3f89 {
  strings:
    $key_3f89 = { 68 fb [2] 5a d9 [2] 5c ec [2] 72 ec [2] 4d f0 }

  condition:
    any of them
}