rule TTP_XOR_WriteProcessMemory_621d {
  strings:
    $key_621d = { 35 6f [2] 07 4d [2] 01 78 [2] 2f 78 [2] 10 64 }

  condition:
    any of them
}