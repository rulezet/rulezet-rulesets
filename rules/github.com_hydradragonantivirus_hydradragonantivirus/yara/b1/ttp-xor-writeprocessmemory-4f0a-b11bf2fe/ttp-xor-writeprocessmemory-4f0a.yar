rule TTP_XOR_WriteProcessMemory_4f0a {
  strings:
    $key_4f0a = { 18 78 [2] 2a 5a [2] 2c 6f [2] 02 6f [2] 3d 73 }

  condition:
    any of them
}