rule TTP_XOR_WriteProcessMemory_3edd {
  strings:
    $key_3edd = { 69 af [2] 5b 8d [2] 5d b8 [2] 73 b8 [2] 4c a4 }

  condition:
    any of them
}