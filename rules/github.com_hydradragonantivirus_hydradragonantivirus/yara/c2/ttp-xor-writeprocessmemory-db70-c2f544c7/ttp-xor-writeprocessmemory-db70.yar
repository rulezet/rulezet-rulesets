rule TTP_XOR_WriteProcessMemory_db70 {
  strings:
    $key_db70 = { 8c 02 [2] be 20 [2] b8 15 [2] 96 15 [2] a9 09 }

  condition:
    any of them
}