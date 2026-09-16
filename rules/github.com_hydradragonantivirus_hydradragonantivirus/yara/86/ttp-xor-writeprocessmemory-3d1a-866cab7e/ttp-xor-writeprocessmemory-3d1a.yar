rule TTP_XOR_WriteProcessMemory_3d1a {
  strings:
    $key_3d1a = { 6a 68 [2] 58 4a [2] 5e 7f [2] 70 7f [2] 4f 63 }

  condition:
    any of them
}