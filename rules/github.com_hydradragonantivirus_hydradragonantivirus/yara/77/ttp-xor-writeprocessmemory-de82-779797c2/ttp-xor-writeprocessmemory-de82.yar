rule TTP_XOR_WriteProcessMemory_de82 {
  strings:
    $key_de82 = { 89 f0 [2] bb d2 [2] bd e7 [2] 93 e7 [2] ac fb }

  condition:
    any of them
}