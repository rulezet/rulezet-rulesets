rule TTP_XOR_WriteProcessMemory_db20 {
  strings:
    $key_db20 = { 8c 52 [2] be 70 [2] b8 45 [2] 96 45 [2] a9 59 }

  condition:
    any of them
}