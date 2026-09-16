rule TTP_XOR_WriteProcessMemory_1e7d {
  strings:
    $key_1e7d = { 49 0f [2] 7b 2d [2] 7d 18 [2] 53 18 [2] 6c 04 }

  condition:
    any of them
}