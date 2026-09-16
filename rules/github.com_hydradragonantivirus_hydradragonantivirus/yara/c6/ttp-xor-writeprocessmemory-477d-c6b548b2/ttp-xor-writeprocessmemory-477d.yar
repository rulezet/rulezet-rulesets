rule TTP_XOR_WriteProcessMemory_477d {
  strings:
    $key_477d = { 10 0f [2] 22 2d [2] 24 18 [2] 0a 18 [2] 35 04 }

  condition:
    any of them
}