rule TTP_XOR_WriteProcessMemory_7c5d {
  strings:
    $key_7c5d = { 2b 2f [2] 19 0d [2] 1f 38 [2] 31 38 [2] 0e 24 }

  condition:
    any of them
}