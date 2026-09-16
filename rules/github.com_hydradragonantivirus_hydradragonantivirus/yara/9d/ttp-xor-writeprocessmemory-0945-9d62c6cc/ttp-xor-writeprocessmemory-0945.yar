rule TTP_XOR_WriteProcessMemory_0945 {
  strings:
    $key_0945 = { 5e 37 [2] 6c 15 [2] 6a 20 [2] 44 20 [2] 7b 3c }

  condition:
    any of them
}