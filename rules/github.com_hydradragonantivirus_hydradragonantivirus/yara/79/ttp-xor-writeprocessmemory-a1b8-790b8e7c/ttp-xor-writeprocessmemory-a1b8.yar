rule TTP_XOR_WriteProcessMemory_a1b8 {
  strings:
    $key_a1b8 = { f6 ca [2] c4 e8 [2] c2 dd [2] ec dd [2] d3 c1 }

  condition:
    any of them
}