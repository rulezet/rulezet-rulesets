rule TTP_XOR_WriteProcessMemory_db38 {
  strings:
    $key_db38 = { 8c 4a [2] be 68 [2] b8 5d [2] 96 5d [2] a9 41 }

  condition:
    any of them
}