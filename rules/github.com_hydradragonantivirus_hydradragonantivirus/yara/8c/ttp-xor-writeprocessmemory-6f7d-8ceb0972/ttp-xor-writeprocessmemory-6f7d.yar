rule TTP_XOR_WriteProcessMemory_6f7d {
  strings:
    $key_6f7d = { 38 0f [2] 0a 2d [2] 0c 18 [2] 22 18 [2] 1d 04 }

  condition:
    any of them
}