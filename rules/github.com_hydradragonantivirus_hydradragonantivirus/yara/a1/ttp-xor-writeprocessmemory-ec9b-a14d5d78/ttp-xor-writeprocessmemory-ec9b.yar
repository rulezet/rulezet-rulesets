rule TTP_XOR_WriteProcessMemory_ec9b {
  strings:
    $key_ec9b = { bb e9 [2] 89 cb [2] 8f fe [2] a1 fe [2] 9e e2 }

  condition:
    any of them
}