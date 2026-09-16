rule TTP_XOR_WriteProcessMemory_afa1 {
  strings:
    $key_afa1 = { f8 d3 [2] ca f1 [2] cc c4 [2] e2 c4 [2] dd d8 }

  condition:
    any of them
}