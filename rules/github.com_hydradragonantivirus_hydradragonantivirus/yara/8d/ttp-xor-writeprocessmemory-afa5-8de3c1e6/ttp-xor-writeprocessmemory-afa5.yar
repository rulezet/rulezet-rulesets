rule TTP_XOR_WriteProcessMemory_afa5 {
  strings:
    $key_afa5 = { f8 d7 [2] ca f5 [2] cc c0 [2] e2 c0 [2] dd dc }

  condition:
    any of them
}