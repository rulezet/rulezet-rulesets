rule TTP_XOR_WriteProcessMemory_562d {
  strings:
    $key_562d = { 01 5f [2] 33 7d [2] 35 48 [2] 1b 48 [2] 24 54 }

  condition:
    any of them
}