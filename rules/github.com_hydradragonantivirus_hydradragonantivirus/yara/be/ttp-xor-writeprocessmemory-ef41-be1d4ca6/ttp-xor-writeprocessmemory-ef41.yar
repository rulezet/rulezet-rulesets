rule TTP_XOR_WriteProcessMemory_ef41 {
  strings:
    $key_ef41 = { b8 33 [2] 8a 11 [2] 8c 24 [2] a2 24 [2] 9d 38 }

  condition:
    any of them
}