rule TTP_XOR_WriteProcessMemory_a1e9 {
  strings:
    $key_a1e9 = { f6 9b [2] c4 b9 [2] c2 8c [2] ec 8c [2] d3 90 }

  condition:
    any of them
}