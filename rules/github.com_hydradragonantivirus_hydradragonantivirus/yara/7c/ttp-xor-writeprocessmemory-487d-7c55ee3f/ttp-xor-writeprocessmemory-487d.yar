rule TTP_XOR_WriteProcessMemory_487d {
  strings:
    $key_487d = { 1f 0f [2] 2d 2d [2] 2b 18 [2] 05 18 [2] 3a 04 }

  condition:
    any of them
}