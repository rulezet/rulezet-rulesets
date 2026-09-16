rule TTP_XOR_WriteProcessMemory_7c3d {
  strings:
    $key_7c3d = { 2b 4f [2] 19 6d [2] 1f 58 [2] 31 58 [2] 0e 44 }

  condition:
    any of them
}