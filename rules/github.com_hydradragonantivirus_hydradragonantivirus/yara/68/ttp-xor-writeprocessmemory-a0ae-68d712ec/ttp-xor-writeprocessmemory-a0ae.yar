rule TTP_XOR_WriteProcessMemory_a0ae {
  strings:
    $key_a0ae = { f7 dc [2] c5 fe [2] c3 cb [2] ed cb [2] d2 d7 }

  condition:
    any of them
}