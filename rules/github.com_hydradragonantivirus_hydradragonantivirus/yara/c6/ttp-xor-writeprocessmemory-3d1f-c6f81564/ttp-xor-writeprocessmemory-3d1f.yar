rule TTP_XOR_WriteProcessMemory_3d1f {
  strings:
    $key_3d1f = { 6a 6d [2] 58 4f [2] 5e 7a [2] 70 7a [2] 4f 66 }

  condition:
    any of them
}