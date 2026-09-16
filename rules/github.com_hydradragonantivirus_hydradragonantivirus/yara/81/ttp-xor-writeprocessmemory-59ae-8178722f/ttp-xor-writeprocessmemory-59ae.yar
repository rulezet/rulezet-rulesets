rule TTP_XOR_WriteProcessMemory_59ae {
  strings:
    $key_59ae = { 0e dc [2] 3c fe [2] 3a cb [2] 14 cb [2] 2b d7 }

  condition:
    any of them
}