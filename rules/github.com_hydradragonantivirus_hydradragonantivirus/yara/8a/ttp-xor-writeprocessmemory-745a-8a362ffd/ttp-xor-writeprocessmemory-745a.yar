rule TTP_XOR_WriteProcessMemory_745a {
  strings:
    $key_745a = { 23 28 [2] 11 0a [2] 17 3f [2] 39 3f [2] 06 23 }

  condition:
    any of them
}