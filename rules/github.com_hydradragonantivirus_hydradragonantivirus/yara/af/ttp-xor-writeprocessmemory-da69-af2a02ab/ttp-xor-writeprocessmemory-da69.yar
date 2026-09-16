rule TTP_XOR_WriteProcessMemory_da69 {
  strings:
    $key_da69 = { 8d 1b [2] bf 39 [2] b9 0c [2] 97 0c [2] a8 10 }

  condition:
    any of them
}