rule TTP_XOR_WriteProcessMemory_c93d {
  strings:
    $key_c93d = { 9e 4f [2] ac 6d [2] aa 58 [2] 84 58 [2] bb 44 }

  condition:
    any of them
}