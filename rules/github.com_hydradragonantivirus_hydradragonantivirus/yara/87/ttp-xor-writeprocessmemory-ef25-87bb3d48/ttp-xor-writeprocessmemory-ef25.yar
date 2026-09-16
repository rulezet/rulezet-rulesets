rule TTP_XOR_WriteProcessMemory_ef25 {
  strings:
    $key_ef25 = { b8 57 [2] 8a 75 [2] 8c 40 [2] a2 40 [2] 9d 5c }

  condition:
    any of them
}