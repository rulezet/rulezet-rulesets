rule TTP_XOR_WriteProcessMemory_a159 {
  strings:
    $key_a159 = { f6 2b [2] c4 09 [2] c2 3c [2] ec 3c [2] d3 20 }

  condition:
    any of them
}