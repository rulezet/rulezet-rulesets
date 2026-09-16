rule TTP_XOR_WriteProcessMemory_373d {
  strings:
    $key_373d = { 60 4f [2] 52 6d [2] 54 58 [2] 7a 58 [2] 45 44 }

  condition:
    any of them
}