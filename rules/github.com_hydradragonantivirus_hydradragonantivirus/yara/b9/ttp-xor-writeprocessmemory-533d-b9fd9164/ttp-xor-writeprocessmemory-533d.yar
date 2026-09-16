rule TTP_XOR_WriteProcessMemory_533d {
  strings:
    $key_533d = { 04 4f [2] 36 6d [2] 30 58 [2] 1e 58 [2] 21 44 }

  condition:
    any of them
}