rule TTP_XOR_WriteProcessMemory_5a5d {
  strings:
    $key_5a5d = { 0d 2f [2] 3f 0d [2] 39 38 [2] 17 38 [2] 28 24 }

  condition:
    any of them
}