rule TTP_XOR_WriteProcessMemory_d025 {
  strings:
    $key_d025 = { 87 57 [2] b5 75 [2] b3 40 [2] 9d 40 [2] a2 5c }

  condition:
    any of them
}