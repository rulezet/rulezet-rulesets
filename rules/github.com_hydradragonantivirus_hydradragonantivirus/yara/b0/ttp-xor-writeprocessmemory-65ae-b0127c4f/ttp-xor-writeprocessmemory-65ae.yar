rule TTP_XOR_WriteProcessMemory_65ae {
  strings:
    $key_65ae = { 32 dc [2] 00 fe [2] 06 cb [2] 28 cb [2] 17 d7 }

  condition:
    any of them
}