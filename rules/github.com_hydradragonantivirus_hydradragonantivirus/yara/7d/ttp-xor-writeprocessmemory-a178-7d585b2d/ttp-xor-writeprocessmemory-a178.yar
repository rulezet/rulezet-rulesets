rule TTP_XOR_WriteProcessMemory_a178 {
  strings:
    $key_a178 = { f6 0a [2] c4 28 [2] c2 1d [2] ec 1d [2] d3 01 }

  condition:
    any of them
}