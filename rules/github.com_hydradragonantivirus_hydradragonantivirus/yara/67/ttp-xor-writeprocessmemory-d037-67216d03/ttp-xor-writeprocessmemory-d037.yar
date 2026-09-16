rule TTP_XOR_WriteProcessMemory_d037 {
  strings:
    $key_d037 = { 87 45 [2] b5 67 [2] b3 52 [2] 9d 52 [2] a2 4e }

  condition:
    any of them
}