rule TTP_XOR_WriteProcessMemory_4c7d {
  strings:
    $key_4c7d = { 1b 0f [2] 29 2d [2] 2f 18 [2] 01 18 [2] 3e 04 }

  condition:
    any of them
}