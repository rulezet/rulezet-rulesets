rule TTP_XOR_WriteProcessMemory_470d {
  strings:
    $key_470d = { 10 7f [2] 22 5d [2] 24 68 [2] 0a 68 [2] 35 74 }

  condition:
    any of them
}