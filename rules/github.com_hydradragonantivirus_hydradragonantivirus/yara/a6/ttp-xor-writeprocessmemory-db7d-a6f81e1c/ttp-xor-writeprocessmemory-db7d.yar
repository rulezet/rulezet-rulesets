rule TTP_XOR_WriteProcessMemory_db7d {
  strings:
    $key_db7d = { 8c 0f [2] be 2d [2] b8 18 [2] 96 18 [2] a9 04 }

  condition:
    any of them
}