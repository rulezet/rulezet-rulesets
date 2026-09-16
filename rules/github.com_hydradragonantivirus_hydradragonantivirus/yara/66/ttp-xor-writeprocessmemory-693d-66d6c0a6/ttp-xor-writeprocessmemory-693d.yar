rule TTP_XOR_WriteProcessMemory_693d {
  strings:
    $key_693d = { 3e 4f [2] 0c 6d [2] 0a 58 [2] 24 58 [2] 1b 44 }

  condition:
    any of them
}