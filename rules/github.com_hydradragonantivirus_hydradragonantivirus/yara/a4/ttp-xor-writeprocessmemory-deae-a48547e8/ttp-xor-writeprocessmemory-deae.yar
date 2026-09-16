rule TTP_XOR_WriteProcessMemory_deae {
  strings:
    $key_deae = { 89 dc [2] bb fe [2] bd cb [2] 93 cb [2] ac d7 }

  condition:
    any of them
}