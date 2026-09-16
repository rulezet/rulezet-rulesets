rule TTP_XOR_WriteProcessMemory_ef61 {
  strings:
    $key_ef61 = { b8 13 [2] 8a 31 [2] 8c 04 [2] a2 04 [2] 9d 18 }

  condition:
    any of them
}