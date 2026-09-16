rule TTP_XOR_WriteProcessMemory_a1ae {
  strings:
    $key_a1ae = { f6 dc [2] c4 fe [2] c2 cb [2] ec cb [2] d3 d7 }

  condition:
    any of them
}