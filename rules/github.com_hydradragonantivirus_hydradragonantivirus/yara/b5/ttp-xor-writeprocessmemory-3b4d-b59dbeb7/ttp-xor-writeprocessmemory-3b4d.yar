rule TTP_XOR_WriteProcessMemory_3b4d {
  strings:
    $key_3b4d = { 6c 3f [2] 5e 1d [2] 58 28 [2] 76 28 [2] 49 34 }

  condition:
    any of them
}