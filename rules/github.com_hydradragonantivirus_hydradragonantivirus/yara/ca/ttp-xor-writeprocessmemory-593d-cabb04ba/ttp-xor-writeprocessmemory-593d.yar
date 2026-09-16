rule TTP_XOR_WriteProcessMemory_593d {
  strings:
    $key_593d = { 0e 4f [2] 3c 6d [2] 3a 58 [2] 14 58 [2] 2b 44 }

  condition:
    any of them
}