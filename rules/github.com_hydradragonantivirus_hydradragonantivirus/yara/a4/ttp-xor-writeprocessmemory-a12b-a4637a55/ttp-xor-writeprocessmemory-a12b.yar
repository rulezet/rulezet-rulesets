rule TTP_XOR_WriteProcessMemory_a12b {
  strings:
    $key_a12b = { f6 59 [2] c4 7b [2] c2 4e [2] ec 4e [2] d3 52 }

  condition:
    any of them
}