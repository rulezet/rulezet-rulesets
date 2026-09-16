rule TTP_XOR_WriteProcessMemory_6a2a {
  strings:
    $key_6a2a = { 3d 58 [2] 0f 7a [2] 09 4f [2] 27 4f [2] 18 53 }

  condition:
    any of them
}