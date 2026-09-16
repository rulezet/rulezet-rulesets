rule TTP_XOR_WriteProcessMemory_4edd {
  strings:
    $key_4edd = { 19 af [2] 2b 8d [2] 2d b8 [2] 03 b8 [2] 3c a4 }

  condition:
    any of them
}