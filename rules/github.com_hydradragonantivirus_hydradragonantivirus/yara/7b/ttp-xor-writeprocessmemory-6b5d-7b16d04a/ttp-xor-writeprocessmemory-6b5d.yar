rule TTP_XOR_WriteProcessMemory_6b5d {
  strings:
    $key_6b5d = { 3c 2f [2] 0e 0d [2] 08 38 [2] 26 38 [2] 19 24 }

  condition:
    any of them
}