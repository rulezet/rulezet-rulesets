rule TTP_XOR_WriteProcessMemory_586a {
  strings:
    $key_586a = { 0f 18 [2] 3d 3a [2] 3b 0f [2] 15 0f [2] 2a 13 }

  condition:
    any of them
}