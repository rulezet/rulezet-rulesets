rule TTP_XOR_WriteProcessMemory_3d0a {
  strings:
    $key_3d0a = { 6a 78 [2] 58 5a [2] 5e 6f [2] 70 6f [2] 4f 73 }

  condition:
    any of them
}