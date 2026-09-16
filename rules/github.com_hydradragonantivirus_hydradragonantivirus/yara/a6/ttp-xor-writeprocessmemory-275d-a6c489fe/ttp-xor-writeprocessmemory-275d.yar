rule TTP_XOR_WriteProcessMemory_275d {
  strings:
    $key_275d = { 70 2f [2] 42 0d [2] 44 38 [2] 6a 38 [2] 55 24 }

  condition:
    any of them
}