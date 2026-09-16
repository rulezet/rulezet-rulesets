rule TTP_XOR_WriteProcessMemory_3f4d {
  strings:
    $key_3f4d = { 68 3f [2] 5a 1d [2] 5c 28 [2] 72 28 [2] 4d 34 }

  condition:
    any of them
}