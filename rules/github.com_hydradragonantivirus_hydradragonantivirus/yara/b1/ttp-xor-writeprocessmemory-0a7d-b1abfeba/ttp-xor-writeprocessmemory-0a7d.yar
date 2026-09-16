rule TTP_XOR_WriteProcessMemory_0a7d {
  strings:
    $key_0a7d = { 5d 0f [2] 6f 2d [2] 69 18 [2] 47 18 [2] 78 04 }

  condition:
    any of them
}