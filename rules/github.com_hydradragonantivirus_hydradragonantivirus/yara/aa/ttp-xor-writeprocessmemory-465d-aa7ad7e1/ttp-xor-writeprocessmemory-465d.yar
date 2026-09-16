rule TTP_XOR_WriteProcessMemory_465d {
  strings:
    $key_465d = { 11 2f [2] 23 0d [2] 25 38 [2] 0b 38 [2] 34 24 }

  condition:
    any of them
}