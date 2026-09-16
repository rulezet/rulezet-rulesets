rule TTP_XOR_WriteProcessMemory_6a6a {
  strings:
    $key_6a6a = { 3d 18 [2] 0f 3a [2] 09 0f [2] 27 0f [2] 18 13 }

  condition:
    any of them
}