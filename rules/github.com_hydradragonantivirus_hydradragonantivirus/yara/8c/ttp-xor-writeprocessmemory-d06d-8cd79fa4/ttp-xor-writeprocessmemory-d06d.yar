rule TTP_XOR_WriteProcessMemory_d06d {
  strings:
    $key_d06d = { 87 1f [2] b5 3d [2] b3 08 [2] 9d 08 [2] a2 14 }

  condition:
    any of them
}