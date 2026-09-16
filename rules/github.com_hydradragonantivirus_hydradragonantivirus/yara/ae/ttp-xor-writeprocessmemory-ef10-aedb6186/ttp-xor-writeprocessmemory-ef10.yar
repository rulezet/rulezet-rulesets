rule TTP_XOR_WriteProcessMemory_ef10 {
  strings:
    $key_ef10 = { b8 62 [2] 8a 40 [2] 8c 75 [2] a2 75 [2] 9d 69 }

  condition:
    any of them
}