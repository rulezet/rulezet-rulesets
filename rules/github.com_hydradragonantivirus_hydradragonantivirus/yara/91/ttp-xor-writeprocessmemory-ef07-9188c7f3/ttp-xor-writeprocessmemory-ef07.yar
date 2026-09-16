rule TTP_XOR_WriteProcessMemory_ef07 {
  strings:
    $key_ef07 = { b8 75 [2] 8a 57 [2] 8c 62 [2] a2 62 [2] 9d 7e }

  condition:
    any of them
}