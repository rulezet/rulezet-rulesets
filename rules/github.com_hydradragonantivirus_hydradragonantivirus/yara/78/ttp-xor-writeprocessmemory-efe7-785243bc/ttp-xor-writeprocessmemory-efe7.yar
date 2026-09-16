rule TTP_XOR_WriteProcessMemory_efe7 {
  strings:
    $key_efe7 = { b8 95 [2] 8a b7 [2] 8c 82 [2] a2 82 [2] 9d 9e }

  condition:
    any of them
}