rule TTP_XOR_WriteProcessMemory_fcf2 {
  strings:
    $key_fcf2 = { ab 80 [2] 99 a2 [2] 9f 97 [2] b1 97 [2] 8e 8b }

  condition:
    any of them
}