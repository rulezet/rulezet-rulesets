rule TTP_XOR_WriteProcessMemory_d602 {
  strings:
    $key_d602 = { 81 70 [2] b3 52 [2] b5 67 [2] 9b 67 [2] a4 7b }

  condition:
    any of them
}