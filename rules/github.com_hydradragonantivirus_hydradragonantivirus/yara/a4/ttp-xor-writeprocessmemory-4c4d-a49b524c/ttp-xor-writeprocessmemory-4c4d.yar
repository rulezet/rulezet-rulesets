rule TTP_XOR_WriteProcessMemory_4c4d {
  strings:
    $key_4c4d = { 1b 3f [2] 29 1d [2] 2f 28 [2] 01 28 [2] 3e 34 }

  condition:
    any of them
}