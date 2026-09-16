rule TTP_XOR_WriteProcessMemory_542f {
  strings:
    $key_542f = { 03 5d [2] 31 7f [2] 37 4a [2] 19 4a [2] 26 56 }

  condition:
    any of them
}