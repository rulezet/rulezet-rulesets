rule TTP_XOR_WriteProcessMemory_37ae {
  strings:
    $key_37ae = { 60 dc [2] 52 fe [2] 54 cb [2] 7a cb [2] 45 d7 }

  condition:
    any of them
}