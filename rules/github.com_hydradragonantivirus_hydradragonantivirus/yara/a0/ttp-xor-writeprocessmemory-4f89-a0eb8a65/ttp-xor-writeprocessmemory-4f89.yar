rule TTP_XOR_WriteProcessMemory_4f89 {
  strings:
    $key_4f89 = { 18 fb [2] 2a d9 [2] 2c ec [2] 02 ec [2] 3d f0 }

  condition:
    any of them
}