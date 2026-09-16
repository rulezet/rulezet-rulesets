rule TTP_XOR_WriteProcessMemory_1c5d {
  strings:
    $key_1c5d = { 4b 2f [2] 79 0d [2] 7f 38 [2] 51 38 [2] 6e 24 }

  condition:
    any of them
}