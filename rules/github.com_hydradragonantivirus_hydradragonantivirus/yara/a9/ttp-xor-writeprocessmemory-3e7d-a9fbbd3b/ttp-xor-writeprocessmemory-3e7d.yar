rule TTP_XOR_WriteProcessMemory_3e7d {
  strings:
    $key_3e7d = { 69 0f [2] 5b 2d [2] 5d 18 [2] 73 18 [2] 4c 04 }

  condition:
    any of them
}