rule TTP_XOR_WriteProcessMemory_2e7d {
  strings:
    $key_2e7d = { 79 0f [2] 4b 2d [2] 4d 18 [2] 63 18 [2] 5c 04 }

  condition:
    any of them
}