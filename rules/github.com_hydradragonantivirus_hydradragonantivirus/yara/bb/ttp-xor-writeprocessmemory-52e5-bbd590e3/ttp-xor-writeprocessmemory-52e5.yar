rule TTP_XOR_WriteProcessMemory_52e5 {
  strings:
    $key_52e5 = { 05 97 [2] 37 b5 [2] 31 80 [2] 1f 80 [2] 20 9c }

  condition:
    any of them
}