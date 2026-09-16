rule TTP_XOR_WriteProcessMemory_2e3d {
  strings:
    $key_2e3d = { 79 4f [2] 4b 6d [2] 4d 58 [2] 63 58 [2] 5c 44 }

  condition:
    any of them
}