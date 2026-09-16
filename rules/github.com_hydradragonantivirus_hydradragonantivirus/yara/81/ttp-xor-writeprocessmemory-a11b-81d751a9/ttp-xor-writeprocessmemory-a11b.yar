rule TTP_XOR_WriteProcessMemory_a11b {
  strings:
    $key_a11b = { f6 69 [2] c4 4b [2] c2 7e [2] ec 7e [2] d3 62 }

  condition:
    any of them
}