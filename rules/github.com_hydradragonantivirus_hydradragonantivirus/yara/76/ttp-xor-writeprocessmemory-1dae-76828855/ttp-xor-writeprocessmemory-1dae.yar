rule TTP_XOR_WriteProcessMemory_1dae {
  strings:
    $key_1dae = { 4a dc [2] 78 fe [2] 7e cb [2] 50 cb [2] 6f d7 }

  condition:
    any of them
}