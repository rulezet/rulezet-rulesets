rule TTP_XOR_WriteProcessMemory_da6d {
  strings:
    $key_da6d = { 8d 1f [2] bf 3d [2] b9 08 [2] 97 08 [2] a8 14 }

  condition:
    any of them
}