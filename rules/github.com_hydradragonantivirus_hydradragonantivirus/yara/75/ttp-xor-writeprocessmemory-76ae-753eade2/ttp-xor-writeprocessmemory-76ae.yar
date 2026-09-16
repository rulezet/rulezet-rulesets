rule TTP_XOR_WriteProcessMemory_76ae {
  strings:
    $key_76ae = { 21 dc [2] 13 fe [2] 15 cb [2] 3b cb [2] 04 d7 }

  condition:
    any of them
}