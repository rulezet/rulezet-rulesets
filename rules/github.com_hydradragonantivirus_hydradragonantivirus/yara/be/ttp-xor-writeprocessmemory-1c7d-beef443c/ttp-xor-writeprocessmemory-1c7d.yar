rule TTP_XOR_WriteProcessMemory_1c7d {
  strings:
    $key_1c7d = { 4b 0f [2] 79 2d [2] 7f 18 [2] 51 18 [2] 6e 04 }

  condition:
    any of them
}