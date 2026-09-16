rule TTP_XOR_WriteProcessMemory_675f {
  strings:
    $key_675f = { 30 2d [2] 02 0f [2] 04 3a [2] 2a 3a [2] 15 26 }

  condition:
    any of them
}