rule TTP_XOR_WriteProcessMemory_ef45 {
  strings:
    $key_ef45 = { b8 37 [2] 8a 15 [2] 8c 20 [2] a2 20 [2] 9d 3c }

  condition:
    any of them
}