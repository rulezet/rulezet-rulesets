rule TTP_XOR_WriteProcessMemory_e945 {
  strings:
    $key_e945 = { be 37 [2] 8c 15 [2] 8a 20 [2] a4 20 [2] 9b 3c }

  condition:
    any of them
}