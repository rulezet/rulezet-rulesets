rule TTP_XOR_WriteProcessMemory_ed89 {
  strings:
    $key_ed89 = { ba fb [2] 88 d9 [2] 8e ec [2] a0 ec [2] 9f f0 }

  condition:
    any of them
}