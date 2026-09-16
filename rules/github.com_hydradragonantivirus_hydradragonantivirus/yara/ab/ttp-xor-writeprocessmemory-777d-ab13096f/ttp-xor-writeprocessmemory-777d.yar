rule TTP_XOR_WriteProcessMemory_777d {
  strings:
    $key_777d = { 20 0f [2] 12 2d [2] 14 18 [2] 3a 18 [2] 05 04 }

  condition:
    any of them
}