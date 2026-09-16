rule TTP_XOR_WriteProcessMemory_67cb {
  strings:
    $key_67cb = { 30 b9 [2] 02 9b [2] 04 ae [2] 2a ae [2] 15 b2 }

  condition:
    any of them
}