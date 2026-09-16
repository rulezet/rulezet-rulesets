rule TTP_XOR_WriteProcessMemory_a289 {
  strings:
    $key_a289 = { f5 fb [2] c7 d9 [2] c1 ec [2] ef ec [2] d0 f0 }

  condition:
    any of them
}