rule TTP_XOR_WriteProcessMemory_fcf4 {
  strings:
    $key_fcf4 = { ab 86 [2] 99 a4 [2] 9f 91 [2] b1 91 [2] 8e 8d }

  condition:
    any of them
}