rule TTP_XOR_WriteProcessMemory_752d {
  strings:
    $key_752d = { 22 5f [2] 10 7d [2] 16 48 [2] 38 48 [2] 07 54 }

  condition:
    any of them
}