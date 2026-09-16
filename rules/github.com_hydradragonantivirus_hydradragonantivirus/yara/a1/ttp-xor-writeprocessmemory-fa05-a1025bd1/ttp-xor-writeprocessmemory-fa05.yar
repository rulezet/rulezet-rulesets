rule TTP_XOR_WriteProcessMemory_fa05 {
  strings:
    $key_fa05 = { ad 77 [2] 9f 55 [2] 99 60 [2] b7 60 [2] 88 7c }

  condition:
    any of them
}