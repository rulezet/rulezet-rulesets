rule TTP_XOR_WriteProcessMemory_a1b5 {
  strings:
    $key_a1b5 = { f6 c7 [2] c4 e5 [2] c2 d0 [2] ec d0 [2] d3 cc }

  condition:
    any of them
}