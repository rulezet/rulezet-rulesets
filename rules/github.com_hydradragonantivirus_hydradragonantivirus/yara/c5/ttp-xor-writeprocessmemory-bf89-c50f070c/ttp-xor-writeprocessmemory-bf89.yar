rule TTP_XOR_WriteProcessMemory_bf89 {
  strings:
    $key_bf89 = { e8 fb [2] da d9 [2] dc ec [2] f2 ec [2] cd f0 }

  condition:
    any of them
}