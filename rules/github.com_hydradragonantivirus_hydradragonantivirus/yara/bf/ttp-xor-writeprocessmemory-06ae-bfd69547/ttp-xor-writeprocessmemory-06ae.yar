rule TTP_XOR_WriteProcessMemory_06ae {
  strings:
    $key_06ae = { 51 dc [2] 63 fe [2] 65 cb [2] 4b cb [2] 74 d7 }

  condition:
    any of them
}