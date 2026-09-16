rule TTP_XOR_WriteProcessMemory_544d {
  strings:
    $key_544d = { 03 3f [2] 31 1d [2] 37 28 [2] 19 28 [2] 26 34 }

  condition:
    any of them
}