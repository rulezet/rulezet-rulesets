rule TTP_XOR_WriteProcessMemory_2e2d {
  strings:
    $key_2e2d = { 79 5f [2] 4b 7d [2] 4d 48 [2] 63 48 [2] 5c 54 }

  condition:
    any of them
}