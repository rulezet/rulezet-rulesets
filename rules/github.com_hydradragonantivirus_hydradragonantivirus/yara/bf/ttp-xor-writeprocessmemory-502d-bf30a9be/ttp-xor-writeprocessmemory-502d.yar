rule TTP_XOR_WriteProcessMemory_502d {
  strings:
    $key_502d = { 07 5f [2] 35 7d [2] 33 48 [2] 1d 48 [2] 22 54 }

  condition:
    any of them
}