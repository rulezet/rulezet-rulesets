rule TTP_XOR_WriteProcessMemory_03e5 {
  strings:
    $key_03e5 = { 54 97 [2] 66 b5 [2] 60 80 [2] 4e 80 [2] 71 9c }

  condition:
    any of them
}