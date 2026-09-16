rule TTP_XOR_WriteProcessMemory_49ae {
  strings:
    $key_49ae = { 1e dc [2] 2c fe [2] 2a cb [2] 04 cb [2] 3b d7 }

  condition:
    any of them
}