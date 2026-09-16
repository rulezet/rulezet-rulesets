rule TTP_XOR_WriteProcessMemory_a107 {
  strings:
    $key_a107 = { f6 75 [2] c4 57 [2] c2 62 [2] ec 62 [2] d3 7e }

  condition:
    any of them
}