rule TTP_XOR_WriteProcessMemory_0a5d {
  strings:
    $key_0a5d = { 5d 2f [2] 6f 0d [2] 69 38 [2] 47 38 [2] 78 24 }

  condition:
    any of them
}