rule TTP_XOR_WriteProcessMemory_3e2d {
  strings:
    $key_3e2d = { 69 5f [2] 5b 7d [2] 5d 48 [2] 73 48 [2] 4c 54 }

  condition:
    any of them
}