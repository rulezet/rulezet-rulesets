rule TTP_XOR_WriteProcessMemory_cfae {
  strings:
    $key_cfae = { 98 dc [2] aa fe [2] ac cb [2] 82 cb [2] bd d7 }

  condition:
    any of them
}