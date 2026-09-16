rule TTP_XOR_WriteProcessMemory_ee9e {
  strings:
    $key_ee9e = { b9 ec [2] 8b ce [2] 8d fb [2] a3 fb [2] 9c e7 }

  condition:
    any of them
}