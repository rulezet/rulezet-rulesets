rule TTP_XOR_WriteProcessMemory_db6d {
  strings:
    $key_db6d = { 8c 1f [2] be 3d [2] b8 08 [2] 96 08 [2] a9 14 }

  condition:
    any of them
}