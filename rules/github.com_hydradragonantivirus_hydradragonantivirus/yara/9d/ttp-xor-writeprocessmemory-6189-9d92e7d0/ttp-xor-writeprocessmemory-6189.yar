rule TTP_XOR_WriteProcessMemory_6189 {
  strings:
    $key_6189 = { 36 fb [2] 04 d9 [2] 02 ec [2] 2c ec [2] 13 f0 }

  condition:
    any of them
}