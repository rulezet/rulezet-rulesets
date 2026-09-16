rule TTP_XOR_WriteProcessMemory_e6ae {
  strings:
    $key_e6ae = { b1 dc [2] 83 fe [2] 85 cb [2] ab cb [2] 94 d7 }

  condition:
    any of them
}