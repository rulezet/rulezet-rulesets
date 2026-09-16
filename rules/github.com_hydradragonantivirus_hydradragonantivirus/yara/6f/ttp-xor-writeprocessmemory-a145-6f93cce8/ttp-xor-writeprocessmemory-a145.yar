rule TTP_XOR_WriteProcessMemory_a145 {
  strings:
    $key_a145 = { f6 37 [2] c4 15 [2] c2 20 [2] ec 20 [2] d3 3c }

  condition:
    any of them
}