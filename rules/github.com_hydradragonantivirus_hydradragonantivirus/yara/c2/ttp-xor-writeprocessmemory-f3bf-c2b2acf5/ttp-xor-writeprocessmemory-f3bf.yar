rule TTP_XOR_WriteProcessMemory_f3bf {
  strings:
    $key_f3bf = { a4 cd [2] 96 ef [2] 90 da [2] be da [2] 81 c6 }

  condition:
    any of them
}