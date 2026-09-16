rule TTP_XOR_WriteProcessMemory_0c3d {
  strings:
    $key_0c3d = { 5b 4f [2] 69 6d [2] 6f 58 [2] 41 58 [2] 7e 44 }

  condition:
    any of them
}