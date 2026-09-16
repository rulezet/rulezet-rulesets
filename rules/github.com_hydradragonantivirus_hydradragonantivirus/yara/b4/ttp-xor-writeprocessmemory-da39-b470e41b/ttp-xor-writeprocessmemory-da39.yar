rule TTP_XOR_WriteProcessMemory_da39 {
  strings:
    $key_da39 = { 8d 4b [2] bf 69 [2] b9 5c [2] 97 5c [2] a8 40 }

  condition:
    any of them
}