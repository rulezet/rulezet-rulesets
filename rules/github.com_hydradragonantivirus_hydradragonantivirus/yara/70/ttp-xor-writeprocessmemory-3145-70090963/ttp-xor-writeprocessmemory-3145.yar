rule TTP_XOR_WriteProcessMemory_3145 {
  strings:
    $key_3145 = { 66 37 [2] 54 15 [2] 52 20 [2] 7c 20 [2] 43 3c }

  condition:
    any of them
}