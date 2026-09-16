rule TTP_XOR_WriteProcessMemory_582d {
  strings:
    $key_582d = { 0f 5f [2] 3d 7d [2] 3b 48 [2] 15 48 [2] 2a 54 }

  condition:
    any of them
}