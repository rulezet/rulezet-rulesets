rule TTP_XOR_WriteProcessMemory_decd {
  strings:
    $key_decd = { 89 bf [2] bb 9d [2] bd a8 [2] 93 a8 [2] ac b4 }

  condition:
    any of them
}