rule TTP_XOR_WriteProcessMemory_da31 {
  strings:
    $key_da31 = { 8d 43 [2] bf 61 [2] b9 54 [2] 97 54 [2] a8 48 }

  condition:
    any of them
}