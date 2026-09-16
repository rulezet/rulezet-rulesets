rule TTP_XOR_WriteProcessMemory_dece {
  strings:
    $key_dece = { 89 bc [2] bb 9e [2] bd ab [2] 93 ab [2] ac b7 }

  condition:
    any of them
}