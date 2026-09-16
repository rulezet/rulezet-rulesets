rule TTP_XOR_WriteProcessMemory_f8c4 {
  strings:
    $key_f8c4 = { af b6 [2] 9d 94 [2] 9b a1 [2] b5 a1 [2] 8a bd }

  condition:
    any of them
}