rule TTP_XOR_WriteProcessMemory_3e3d {
  strings:
    $key_3e3d = { 69 4f [2] 5b 6d [2] 5d 58 [2] 73 58 [2] 4c 44 }

  condition:
    any of them
}