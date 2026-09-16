rule TTP_XOR_WriteProcessMemory_fa20 {
  strings:
    $key_fa20 = { ad 52 [2] 9f 70 [2] 99 45 [2] b7 45 [2] 88 59 }

  condition:
    any of them
}