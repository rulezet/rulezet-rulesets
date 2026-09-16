rule TTP_XOR_WriteProcessMemory_c92f {
  strings:
    $key_c92f = { 9e 5d [2] ac 7f [2] aa 4a [2] 84 4a [2] bb 56 }

  condition:
    any of them
}