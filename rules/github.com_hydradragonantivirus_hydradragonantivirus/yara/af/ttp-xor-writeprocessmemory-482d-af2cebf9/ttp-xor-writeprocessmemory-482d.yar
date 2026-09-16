rule TTP_XOR_WriteProcessMemory_482d {
  strings:
    $key_482d = { 1f 5f [2] 2d 7d [2] 2b 48 [2] 05 48 [2] 3a 54 }

  condition:
    any of them
}