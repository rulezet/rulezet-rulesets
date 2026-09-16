rule TTP_XOR_WriteProcessMemory_3f7d {
  strings:
    $key_3f7d = { 68 0f [2] 5a 2d [2] 5c 18 [2] 72 18 [2] 4d 04 }

  condition:
    any of them
}