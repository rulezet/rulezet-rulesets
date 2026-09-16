rule TTP_XOR_WriteProcessMemory_4f3a {
  strings:
    $key_4f3a = { 18 48 [2] 2a 6a [2] 2c 5f [2] 02 5f [2] 3d 43 }

  condition:
    any of them
}