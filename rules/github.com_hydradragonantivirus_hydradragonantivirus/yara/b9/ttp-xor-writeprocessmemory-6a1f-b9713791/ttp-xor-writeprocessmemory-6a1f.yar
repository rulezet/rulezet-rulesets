rule TTP_XOR_WriteProcessMemory_6a1f {
  strings:
    $key_6a1f = { 3d 6d [2] 0f 4f [2] 09 7a [2] 27 7a [2] 18 66 }

  condition:
    any of them
}