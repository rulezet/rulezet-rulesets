rule TTP_XOR_WriteProcessMemory_d045 {
  strings:
    $key_d045 = { 87 37 [2] b5 15 [2] b3 20 [2] 9d 20 [2] a2 3c }

  condition:
    any of them
}