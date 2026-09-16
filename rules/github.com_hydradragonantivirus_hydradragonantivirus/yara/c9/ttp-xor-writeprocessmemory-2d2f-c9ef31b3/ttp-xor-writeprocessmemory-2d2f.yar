rule TTP_XOR_WriteProcessMemory_2d2f {
  strings:
    $key_2d2f = { 7a 5d [2] 48 7f [2] 4e 4a [2] 60 4a [2] 5f 56 }

  condition:
    any of them
}