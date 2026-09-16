rule TTP_XOR_WriteProcessMemory_ef05 {
  strings:
    $key_ef05 = { b8 77 [2] 8a 55 [2] 8c 60 [2] a2 60 [2] 9d 7c }

  condition:
    any of them
}