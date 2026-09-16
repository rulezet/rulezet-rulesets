rule TTP_XOR_WriteProcessMemory_fcf8 {
  strings:
    $key_fcf8 = { ab 8a [2] 99 a8 [2] 9f 9d [2] b1 9d [2] 8e 81 }

  condition:
    any of them
}