rule TTP_XOR_WriteProcessMemory_afa2 {
  strings:
    $key_afa2 = { f8 d0 [2] ca f2 [2] cc c7 [2] e2 c7 [2] dd db }

  condition:
    any of them
}