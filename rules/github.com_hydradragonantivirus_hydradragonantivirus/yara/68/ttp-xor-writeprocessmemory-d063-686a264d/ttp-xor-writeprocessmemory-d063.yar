rule TTP_XOR_WriteProcessMemory_d063 {
  strings:
    $key_d063 = { 87 11 [2] b5 33 [2] b3 06 [2] 9d 06 [2] a2 1a }

  condition:
    any of them
}