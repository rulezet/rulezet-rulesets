rule TTP_XOR_WriteProcessMemory_703a {
  strings:
    $key_703a = { 27 48 [2] 15 6a [2] 13 5f [2] 3d 5f [2] 02 43 }

  condition:
    any of them
}