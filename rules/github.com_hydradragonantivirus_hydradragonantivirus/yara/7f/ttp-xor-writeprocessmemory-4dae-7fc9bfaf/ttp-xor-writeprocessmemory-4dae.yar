rule TTP_XOR_WriteProcessMemory_4dae {
  strings:
    $key_4dae = { 1a dc [2] 28 fe [2] 2e cb [2] 00 cb [2] 3f d7 }

  condition:
    any of them
}