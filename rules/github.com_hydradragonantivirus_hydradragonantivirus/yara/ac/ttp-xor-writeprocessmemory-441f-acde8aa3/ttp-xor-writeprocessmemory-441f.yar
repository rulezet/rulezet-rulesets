rule TTP_XOR_WriteProcessMemory_441f {
  strings:
    $key_441f = { 13 6d [2] 21 4f [2] 27 7a [2] 09 7a [2] 36 66 }

  condition:
    any of them
}