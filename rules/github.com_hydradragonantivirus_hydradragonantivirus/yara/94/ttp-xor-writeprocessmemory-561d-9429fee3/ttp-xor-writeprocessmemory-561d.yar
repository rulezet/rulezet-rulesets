rule TTP_XOR_WriteProcessMemory_561d {
  strings:
    $key_561d = { 01 6f [2] 33 4d [2] 35 78 [2] 1b 78 [2] 24 64 }

  condition:
    any of them
}