rule TTP_XOR_WriteProcessMemory_da59 {
  strings:
    $key_da59 = { 8d 2b [2] bf 09 [2] b9 3c [2] 97 3c [2] a8 20 }

  condition:
    any of them
}