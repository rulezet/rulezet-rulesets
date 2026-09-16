rule TTP_XOR_WriteProcessMemory_c95f {
  strings:
    $key_c95f = { 9e 2d [2] ac 0f [2] aa 3a [2] 84 3a [2] bb 26 }

  condition:
    any of them
}