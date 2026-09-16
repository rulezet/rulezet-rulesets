rule TTP_XOR_WriteProcessMemory_8d9b {
  strings:
    $key_8d9b = { da e9 [2] e8 cb [2] ee fe [2] c0 fe [2] ff e2 }

  condition:
    any of them
}