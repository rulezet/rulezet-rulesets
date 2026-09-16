rule TTP_XOR_WriteProcessMemory_a110 {
  strings:
    $key_a110 = { f6 62 [2] c4 40 [2] c2 75 [2] ec 75 [2] d3 69 }

  condition:
    any of them
}