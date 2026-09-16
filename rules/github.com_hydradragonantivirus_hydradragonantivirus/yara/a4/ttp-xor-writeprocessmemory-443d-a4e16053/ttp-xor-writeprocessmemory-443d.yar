rule TTP_XOR_WriteProcessMemory_443d {
  strings:
    $key_443d = { 13 4f [2] 21 6d [2] 27 58 [2] 09 58 [2] 36 44 }

  condition:
    any of them
}