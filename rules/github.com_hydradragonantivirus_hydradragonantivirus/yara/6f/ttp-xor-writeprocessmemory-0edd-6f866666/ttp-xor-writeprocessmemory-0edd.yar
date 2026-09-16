rule TTP_XOR_WriteProcessMemory_0edd {
  strings:
    $key_0edd = { 59 af [2] 6b 8d [2] 6d b8 [2] 43 b8 [2] 7c a4 }

  condition:
    any of them
}