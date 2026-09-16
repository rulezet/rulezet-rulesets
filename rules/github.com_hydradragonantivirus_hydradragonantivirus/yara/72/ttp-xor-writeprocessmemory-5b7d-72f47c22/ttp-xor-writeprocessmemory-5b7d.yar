rule TTP_XOR_WriteProcessMemory_5b7d {
  strings:
    $key_5b7d = { 0c 0f [2] 3e 2d [2] 38 18 [2] 16 18 [2] 29 04 }

  condition:
    any of them
}