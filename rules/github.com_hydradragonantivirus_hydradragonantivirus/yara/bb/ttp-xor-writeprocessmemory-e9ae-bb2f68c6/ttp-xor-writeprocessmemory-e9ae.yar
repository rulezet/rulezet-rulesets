rule TTP_XOR_WriteProcessMemory_e9ae {
  strings:
    $key_e9ae = { be dc [2] 8c fe [2] 8a cb [2] a4 cb [2] 9b d7 }

  condition:
    any of them
}