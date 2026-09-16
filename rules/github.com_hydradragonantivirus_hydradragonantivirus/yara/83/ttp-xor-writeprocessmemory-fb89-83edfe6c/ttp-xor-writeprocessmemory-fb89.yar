rule TTP_XOR_WriteProcessMemory_fb89 {
  strings:
    $key_fb89 = { ac fb [2] 9e d9 [2] 98 ec [2] b6 ec [2] 89 f0 }

  condition:
    any of them
}