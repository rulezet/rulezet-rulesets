rule TTP_XOR_WriteProcessMemory_227d {
  strings:
    $key_227d = { 75 0f [2] 47 2d [2] 41 18 [2] 6f 18 [2] 50 04 }

  condition:
    any of them
}