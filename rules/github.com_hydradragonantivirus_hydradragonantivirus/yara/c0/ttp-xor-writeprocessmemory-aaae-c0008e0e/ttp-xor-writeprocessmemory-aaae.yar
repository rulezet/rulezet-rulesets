rule TTP_XOR_WriteProcessMemory_aaae {
  strings:
    $key_aaae = { fd dc [2] cf fe [2] c9 cb [2] e7 cb [2] d8 d7 }

  condition:
    any of them
}