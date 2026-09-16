rule TTP_XOR_WriteProcessMemory_544a {
  strings:
    $key_544a = { 03 38 [2] 31 1a [2] 37 2f [2] 19 2f [2] 26 33 }

  condition:
    any of them
}