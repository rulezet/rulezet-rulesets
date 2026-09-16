rule TTP_XOR_WriteProcessMemory_0e3d {
  strings:
    $key_0e3d = { 59 4f [2] 6b 6d [2] 6d 58 [2] 43 58 [2] 7c 44 }

  condition:
    any of them
}