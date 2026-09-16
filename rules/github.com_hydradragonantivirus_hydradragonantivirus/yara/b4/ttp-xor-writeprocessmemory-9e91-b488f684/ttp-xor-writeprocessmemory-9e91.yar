rule TTP_XOR_WriteProcessMemory_9e91 {
  strings:
    $key_9e91 = { c9 e3 [2] fb c1 [2] fd f4 [2] d3 f4 [2] ec e8 }

  condition:
    any of them
}