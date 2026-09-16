rule TTP_XOR_WriteProcessMemory_7dae {
  strings:
    $key_7dae = { 2a dc [2] 18 fe [2] 1e cb [2] 30 cb [2] 0f d7 }

  condition:
    any of them
}