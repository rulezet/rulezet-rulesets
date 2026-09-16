rule TTP_XOR_WriteProcessMemory_e13f {
  strings:
    $key_e13f = { b6 4d [2] 84 6f [2] 82 5a [2] ac 5a [2] 93 46 }

  condition:
    any of them
}