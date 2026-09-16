rule TTP_XOR_WriteProcessMemory_e1bf {
  strings:
    $key_e1bf = { b6 cd [2] 84 ef [2] 82 da [2] ac da [2] 93 c6 }

  condition:
    any of them
}