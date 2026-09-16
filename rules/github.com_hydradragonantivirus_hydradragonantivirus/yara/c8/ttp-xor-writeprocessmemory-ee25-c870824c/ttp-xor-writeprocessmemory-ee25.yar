rule TTP_XOR_WriteProcessMemory_ee25 {
  strings:
    $key_ee25 = { b9 57 [2] 8b 75 [2] 8d 40 [2] a3 40 [2] 9c 5c }

  condition:
    any of them
}