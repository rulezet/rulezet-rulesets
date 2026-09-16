rule TTP_XOR_WriteProcessMemory_afa4 {
  strings:
    $key_afa4 = { f8 d6 [2] ca f4 [2] cc c1 [2] e2 c1 [2] dd dd }

  condition:
    any of them
}