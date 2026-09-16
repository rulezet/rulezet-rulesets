rule TTP_XOR_WriteProcessMemory_24ae {
  strings:
    $key_24ae = { 73 dc [2] 41 fe [2] 47 cb [2] 69 cb [2] 56 d7 }

  condition:
    any of them
}