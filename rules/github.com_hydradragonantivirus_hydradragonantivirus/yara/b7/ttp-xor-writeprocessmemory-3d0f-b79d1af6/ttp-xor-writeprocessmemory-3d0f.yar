rule TTP_XOR_WriteProcessMemory_3d0f {
  strings:
    $key_3d0f = { 6a 7d [2] 58 5f [2] 5e 6a [2] 70 6a [2] 4f 76 }

  condition:
    any of them
}