rule TTP_XOR_WriteProcessMemory_5c5d {
  strings:
    $key_5c5d = { 0b 2f [2] 39 0d [2] 3f 38 [2] 11 38 [2] 2e 24 }

  condition:
    any of them
}