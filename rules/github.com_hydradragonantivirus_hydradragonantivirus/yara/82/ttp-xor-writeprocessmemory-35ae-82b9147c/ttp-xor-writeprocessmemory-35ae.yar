rule TTP_XOR_WriteProcessMemory_35ae {
  strings:
    $key_35ae = { 62 dc [2] 50 fe [2] 56 cb [2] 78 cb [2] 47 d7 }

  condition:
    any of them
}