rule TTP_XOR_WriteProcessMemory_b67d {
  strings:
    $key_b67d = { e1 0f [2] d3 2d [2] d5 18 [2] fb 18 [2] c4 04 }

  condition:
    any of them
}