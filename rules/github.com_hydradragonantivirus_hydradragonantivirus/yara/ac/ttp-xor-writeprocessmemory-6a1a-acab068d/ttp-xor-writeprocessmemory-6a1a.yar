rule TTP_XOR_WriteProcessMemory_6a1a {
  strings:
    $key_6a1a = { 3d 68 [2] 0f 4a [2] 09 7f [2] 27 7f [2] 18 63 }

  condition:
    any of them
}