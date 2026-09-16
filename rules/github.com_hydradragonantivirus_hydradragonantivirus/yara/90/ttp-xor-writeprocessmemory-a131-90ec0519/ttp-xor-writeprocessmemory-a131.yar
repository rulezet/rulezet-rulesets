rule TTP_XOR_WriteProcessMemory_a131 {
  strings:
    $key_a131 = { f6 43 [2] c4 61 [2] c2 54 [2] ec 54 [2] d3 48 }

  condition:
    any of them
}