rule TTP_XOR_WriteProcessMemory_a7ae {
  strings:
    $key_a7ae = { f0 dc [2] c2 fe [2] c4 cb [2] ea cb [2] d5 d7 }

  condition:
    any of them
}