rule TTP_XOR_WriteProcessMemory_375d {
  strings:
    $key_375d = { 60 2f [2] 52 0d [2] 54 38 [2] 7a 38 [2] 45 24 }

  condition:
    any of them
}