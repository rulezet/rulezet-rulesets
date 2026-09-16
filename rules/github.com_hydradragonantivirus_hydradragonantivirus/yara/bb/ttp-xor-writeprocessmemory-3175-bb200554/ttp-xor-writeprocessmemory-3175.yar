rule TTP_XOR_WriteProcessMemory_3175 {
  strings:
    $key_3175 = { 66 07 [2] 54 25 [2] 52 10 [2] 7c 10 [2] 43 0c }

  condition:
    any of them
}