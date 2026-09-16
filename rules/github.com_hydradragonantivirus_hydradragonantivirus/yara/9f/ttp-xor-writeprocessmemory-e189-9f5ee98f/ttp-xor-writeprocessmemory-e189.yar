rule TTP_XOR_WriteProcessMemory_e189 {
  strings:
    $key_e189 = { b6 fb [2] 84 d9 [2] 82 ec [2] ac ec [2] 93 f0 }

  condition:
    any of them
}