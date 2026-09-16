rule TTP_XOR_WriteProcessMemory_6a5a {
  strings:
    $key_6a5a = { 3d 28 [2] 0f 0a [2] 09 3f [2] 27 3f [2] 18 23 }

  condition:
    any of them
}