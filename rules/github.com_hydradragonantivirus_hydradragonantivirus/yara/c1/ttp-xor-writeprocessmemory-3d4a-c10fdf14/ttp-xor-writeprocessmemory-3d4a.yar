rule TTP_XOR_WriteProcessMemory_3d4a {
  strings:
    $key_3d4a = { 6a 38 [2] 58 1a [2] 5e 2f [2] 70 2f [2] 4f 33 }

  condition:
    any of them
}