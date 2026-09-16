rule TTP_XOR_WriteProcessMemory_515d {
  strings:
    $key_515d = { 06 2f [2] 34 0d [2] 32 38 [2] 1c 38 [2] 23 24 }

  condition:
    any of them
}