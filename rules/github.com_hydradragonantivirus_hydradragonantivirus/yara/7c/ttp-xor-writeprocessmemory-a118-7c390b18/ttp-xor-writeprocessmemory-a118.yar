rule TTP_XOR_WriteProcessMemory_a118 {
  strings:
    $key_a118 = { f6 6a [2] c4 48 [2] c2 7d [2] ec 7d [2] d3 61 }

  condition:
    any of them
}