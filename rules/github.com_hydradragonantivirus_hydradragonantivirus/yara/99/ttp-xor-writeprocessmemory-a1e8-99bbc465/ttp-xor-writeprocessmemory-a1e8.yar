rule TTP_XOR_WriteProcessMemory_a1e8 {
  strings:
    $key_a1e8 = { f6 9a [2] c4 b8 [2] c2 8d [2] ec 8d [2] d3 91 }

  condition:
    any of them
}