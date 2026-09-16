rule TTP_XOR_WriteProcessMemory_d76d {
  strings:
    $key_d76d = { 80 1f [2] b2 3d [2] b4 08 [2] 9a 08 [2] a5 14 }

  condition:
    any of them
}