rule TTP_XOR_WriteProcessMemory_db61 {
  strings:
    $key_db61 = { 8c 13 [2] be 31 [2] b8 04 [2] 96 04 [2] a9 18 }

  condition:
    any of them
}