rule TTP_XOR_WriteProcessMemory_6c2d {
  strings:
    $key_6c2d = { 3b 5f [2] 09 7d [2] 0f 48 [2] 21 48 [2] 1e 54 }

  condition:
    any of them
}