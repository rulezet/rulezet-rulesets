rule TTP_XOR_WriteProcessMemory_b6cb {
  strings:
    $key_b6cb = { e1 b9 [2] d3 9b [2] d5 ae [2] fb ae [2] c4 b2 }

  condition:
    any of them
}