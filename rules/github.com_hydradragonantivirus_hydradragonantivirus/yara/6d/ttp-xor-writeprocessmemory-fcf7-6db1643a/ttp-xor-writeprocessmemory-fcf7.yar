rule TTP_XOR_WriteProcessMemory_fcf7 {
  strings:
    $key_fcf7 = { ab 85 [2] 99 a7 [2] 9f 92 [2] b1 92 [2] 8e 8e }

  condition:
    any of them
}