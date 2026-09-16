rule TTP_XOR_WriteProcessMemory_fef1 {
  strings:
    $key_fef1 = { a9 83 [2] 9b a1 [2] 9d 94 [2] b3 94 [2] 8c 88 }

  condition:
    any of them
}