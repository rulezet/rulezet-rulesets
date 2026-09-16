rule TTP_XOR_WriteProcessMemory_3d0d {
  strings:
    $key_3d0d = { 6a 7f [2] 58 5d [2] 5e 68 [2] 70 68 [2] 4f 74 }

  condition:
    any of them
}