rule TTP_XOR_WriteProcessMemory_00ae {
  strings:
    $key_00ae = { 57 dc [2] 65 fe [2] 63 cb [2] 4d cb [2] 72 d7 }

  condition:
    any of them
}