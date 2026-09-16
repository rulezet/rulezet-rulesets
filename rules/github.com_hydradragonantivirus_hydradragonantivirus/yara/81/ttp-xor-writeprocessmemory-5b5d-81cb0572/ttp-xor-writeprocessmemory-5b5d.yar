rule TTP_XOR_WriteProcessMemory_5b5d {
  strings:
    $key_5b5d = { 0c 2f [2] 3e 0d [2] 38 38 [2] 16 38 [2] 29 24 }

  condition:
    any of them
}