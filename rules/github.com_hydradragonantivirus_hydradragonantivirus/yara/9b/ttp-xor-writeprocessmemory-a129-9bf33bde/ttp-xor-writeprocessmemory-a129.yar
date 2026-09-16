rule TTP_XOR_WriteProcessMemory_a129 {
  strings:
    $key_a129 = { f6 5b [2] c4 79 [2] c2 4c [2] ec 4c [2] d3 50 }

  condition:
    any of them
}