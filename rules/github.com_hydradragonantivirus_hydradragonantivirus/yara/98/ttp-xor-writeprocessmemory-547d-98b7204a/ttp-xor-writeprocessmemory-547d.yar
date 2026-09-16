rule TTP_XOR_WriteProcessMemory_547d {
  strings:
    $key_547d = { 03 0f [2] 31 2d [2] 37 18 [2] 19 18 [2] 26 04 }

  condition:
    any of them
}