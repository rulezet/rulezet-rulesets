rule TTP_XOR_WriteProcessMemory_7d0d {
  strings:
    $key_7d0d = { 2a 7f [2] 18 5d [2] 1e 68 [2] 30 68 [2] 0f 74 }

  condition:
    any of them
}