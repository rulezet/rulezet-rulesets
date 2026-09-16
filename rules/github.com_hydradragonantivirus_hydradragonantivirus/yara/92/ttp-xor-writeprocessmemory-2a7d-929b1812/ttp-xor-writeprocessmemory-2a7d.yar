rule TTP_XOR_WriteProcessMemory_2a7d {
  strings:
    $key_2a7d = { 7d 0f [2] 4f 2d [2] 49 18 [2] 67 18 [2] 58 04 }

  condition:
    any of them
}