rule TTP_XOR_WriteProcessMemory_a119 {
  strings:
    $key_a119 = { f6 6b [2] c4 49 [2] c2 7c [2] ec 7c [2] d3 60 }

  condition:
    any of them
}