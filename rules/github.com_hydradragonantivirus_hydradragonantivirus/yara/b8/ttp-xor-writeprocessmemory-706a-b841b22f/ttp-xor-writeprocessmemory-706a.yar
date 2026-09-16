rule TTP_XOR_WriteProcessMemory_706a {
  strings:
    $key_706a = { 27 18 [2] 15 3a [2] 13 0f [2] 3d 0f [2] 02 13 }

  condition:
    any of them
}