rule TTP_XOR_WriteProcessMemory_3b5d {
  strings:
    $key_3b5d = { 6c 2f [2] 5e 0d [2] 58 38 [2] 76 38 [2] 49 24 }

  condition:
    any of them
}