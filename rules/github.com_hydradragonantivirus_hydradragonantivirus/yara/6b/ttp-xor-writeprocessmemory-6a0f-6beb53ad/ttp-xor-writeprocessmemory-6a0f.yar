rule TTP_XOR_WriteProcessMemory_6a0f {
  strings:
    $key_6a0f = { 3d 7d [2] 0f 5f [2] 09 6a [2] 27 6a [2] 18 76 }

  condition:
    any of them
}