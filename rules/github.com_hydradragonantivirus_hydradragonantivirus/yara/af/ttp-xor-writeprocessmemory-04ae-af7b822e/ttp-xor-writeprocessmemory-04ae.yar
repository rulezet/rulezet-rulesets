rule TTP_XOR_WriteProcessMemory_04ae {
  strings:
    $key_04ae = { 53 dc [2] 61 fe [2] 67 cb [2] 49 cb [2] 76 d7 }

  condition:
    any of them
}