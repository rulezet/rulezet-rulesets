rule TTP_XOR_WriteProcessMemory_1f7d {
  strings:
    $key_1f7d = { 48 0f [2] 7a 2d [2] 7c 18 [2] 52 18 [2] 6d 04 }

  condition:
    any of them
}