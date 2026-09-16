rule TTP_XOR_WriteProcessMemory_7c2d {
  strings:
    $key_7c2d = { 2b 5f [2] 19 7d [2] 1f 48 [2] 31 48 [2] 0e 54 }

  condition:
    any of them
}