rule TTP_XOR_WriteProcessMemory_d077 {
  strings:
    $key_d077 = { 87 05 [2] b5 27 [2] b3 12 [2] 9d 12 [2] a2 0e }

  condition:
    any of them
}