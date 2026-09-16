rule TTP_XOR_WriteProcessMemory_ffe9 {
  strings:
    $key_ffe9 = { a8 9b [2] 9a b9 [2] 9c 8c [2] b2 8c [2] 8d 90 }

  condition:
    any of them
}