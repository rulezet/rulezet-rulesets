rule TTP_XOR_WriteProcessMemory_1c1d {
  strings:
    $key_1c1d = { 4b 6f [2] 79 4d [2] 7f 78 [2] 51 78 [2] 6e 64 }

  condition:
    any of them
}