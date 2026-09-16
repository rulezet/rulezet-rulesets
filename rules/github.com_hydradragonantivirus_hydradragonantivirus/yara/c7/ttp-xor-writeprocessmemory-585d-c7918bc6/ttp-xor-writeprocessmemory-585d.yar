rule TTP_XOR_WriteProcessMemory_585d {
  strings:
    $key_585d = { 0f 2f [2] 3d 0d [2] 3b 38 [2] 15 38 [2] 2a 24 }

  condition:
    any of them
}