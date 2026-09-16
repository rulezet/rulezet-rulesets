rule TTP_XOR_WriteProcessMemory_583a {
  strings:
    $key_583a = { 0f 48 [2] 3d 6a [2] 3b 5f [2] 15 5f [2] 2a 43 }

  condition:
    any of them
}