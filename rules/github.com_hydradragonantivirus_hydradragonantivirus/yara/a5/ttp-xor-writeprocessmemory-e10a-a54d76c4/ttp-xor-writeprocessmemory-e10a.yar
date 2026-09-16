rule TTP_XOR_WriteProcessMemory_e10a {
  strings:
    $key_e10a = { b6 78 [2] 84 5a [2] 82 6f [2] ac 6f [2] 93 73 }

  condition:
    any of them
}