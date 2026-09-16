rule TTP_XOR_WriteProcessMemory_db48 {
  strings:
    $key_db48 = { 8c 3a [2] be 18 [2] b8 2d [2] 96 2d [2] a9 31 }

  condition:
    any of them
}