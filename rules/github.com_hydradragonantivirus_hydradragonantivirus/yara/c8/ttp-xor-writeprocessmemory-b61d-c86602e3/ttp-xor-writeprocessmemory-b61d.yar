rule TTP_XOR_WriteProcessMemory_b61d {
  strings:
    $key_b61d = { e1 6f [2] d3 4d [2] d5 78 [2] fb 78 [2] c4 64 }

  condition:
    any of them
}