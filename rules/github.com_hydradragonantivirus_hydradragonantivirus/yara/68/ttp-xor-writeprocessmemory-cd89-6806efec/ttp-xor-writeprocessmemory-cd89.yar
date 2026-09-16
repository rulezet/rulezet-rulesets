rule TTP_XOR_WriteProcessMemory_cd89 {
  strings:
    $key_cd89 = { 9a fb [2] a8 d9 [2] ae ec [2] 80 ec [2] bf f0 }

  condition:
    any of them
}