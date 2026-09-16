rule TTP_XOR_WriteProcessMemory_a177 {
  strings:
    $key_a177 = { f6 05 [2] c4 27 [2] c2 12 [2] ec 12 [2] d3 0e }

  condition:
    any of them
}