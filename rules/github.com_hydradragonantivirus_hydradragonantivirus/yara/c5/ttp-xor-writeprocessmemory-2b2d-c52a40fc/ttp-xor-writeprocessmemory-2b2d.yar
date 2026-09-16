rule TTP_XOR_WriteProcessMemory_2b2d {
  strings:
    $key_2b2d = { 7c 5f [2] 4e 7d [2] 48 48 [2] 66 48 [2] 59 54 }

  condition:
    any of them
}