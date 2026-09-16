rule TTP_XOR_WriteProcessMemory_e1ae {
  strings:
    $key_e1ae = { b6 dc [2] 84 fe [2] 82 cb [2] ac cb [2] 93 d7 }

  condition:
    any of them
}