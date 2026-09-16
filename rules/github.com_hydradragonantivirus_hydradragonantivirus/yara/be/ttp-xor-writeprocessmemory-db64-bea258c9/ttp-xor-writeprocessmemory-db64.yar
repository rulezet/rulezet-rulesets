rule TTP_XOR_WriteProcessMemory_db64 {
  strings:
    $key_db64 = { 8c 16 [2] be 34 [2] b8 01 [2] 96 01 [2] a9 1d }

  condition:
    any of them
}