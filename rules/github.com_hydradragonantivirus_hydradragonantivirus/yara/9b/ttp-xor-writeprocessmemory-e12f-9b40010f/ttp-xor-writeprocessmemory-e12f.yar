rule TTP_XOR_WriteProcessMemory_e12f {
  strings:
    $key_e12f = { b6 5d [2] 84 7f [2] 82 4a [2] ac 4a [2] 93 56 }

  condition:
    any of them
}