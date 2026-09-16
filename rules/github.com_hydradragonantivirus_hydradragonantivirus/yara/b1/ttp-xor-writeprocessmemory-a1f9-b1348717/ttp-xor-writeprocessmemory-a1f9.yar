rule TTP_XOR_WriteProcessMemory_a1f9 {
  strings:
    $key_a1f9 = { f6 8b [2] c4 a9 [2] c2 9c [2] ec 9c [2] d3 80 }

  condition:
    any of them
}