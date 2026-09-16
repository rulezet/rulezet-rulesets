rule TTP_XOR_WriteProcessMemory_727d {
  strings:
    $key_727d = { 25 0f [2] 17 2d [2] 11 18 [2] 3f 18 [2] 00 04 }

  condition:
    any of them
}