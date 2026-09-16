rule TTP_XOR_WriteProcessMemory_483d {
  strings:
    $key_483d = { 1f 4f [2] 2d 6d [2] 2b 58 [2] 05 58 [2] 3a 44 }

  condition:
    any of them
}