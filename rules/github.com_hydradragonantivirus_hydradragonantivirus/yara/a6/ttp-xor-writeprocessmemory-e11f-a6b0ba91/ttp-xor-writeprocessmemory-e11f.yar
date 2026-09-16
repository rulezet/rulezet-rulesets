rule TTP_XOR_WriteProcessMemory_e11f {
  strings:
    $key_e11f = { b6 6d [2] 84 4f [2] 82 7a [2] ac 7a [2] 93 66 }

  condition:
    any of them
}