rule TTP_XOR_WriteProcessMemory_e11a {
  strings:
    $key_e11a = { b6 68 [2] 84 4a [2] 82 7f [2] ac 7f [2] 93 63 }

  condition:
    any of them
}