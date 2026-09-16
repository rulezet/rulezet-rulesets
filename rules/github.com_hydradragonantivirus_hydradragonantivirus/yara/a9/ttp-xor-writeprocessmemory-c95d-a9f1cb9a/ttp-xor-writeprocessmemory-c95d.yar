rule TTP_XOR_WriteProcessMemory_c95d {
  strings:
    $key_c95d = { 9e 2f [2] ac 0d [2] aa 38 [2] 84 38 [2] bb 24 }

  condition:
    any of them
}