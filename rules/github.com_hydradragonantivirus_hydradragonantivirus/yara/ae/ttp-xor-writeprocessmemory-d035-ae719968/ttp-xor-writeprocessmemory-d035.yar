rule TTP_XOR_WriteProcessMemory_d035 {
  strings:
    $key_d035 = { 87 47 [2] b5 65 [2] b3 50 [2] 9d 50 [2] a2 4c }

  condition:
    any of them
}