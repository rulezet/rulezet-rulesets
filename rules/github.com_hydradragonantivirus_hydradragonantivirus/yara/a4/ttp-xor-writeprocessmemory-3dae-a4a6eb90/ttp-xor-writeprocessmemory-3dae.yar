rule TTP_XOR_WriteProcessMemory_3dae {
  strings:
    $key_3dae = { 6a dc [2] 58 fe [2] 5e cb [2] 70 cb [2] 4f d7 }

  condition:
    any of them
}