rule TTP_XOR_WriteProcessMemory_2edd {
  strings:
    $key_2edd = { 79 af [2] 4b 8d [2] 4d b8 [2] 63 b8 [2] 5c a4 }

  condition:
    any of them
}