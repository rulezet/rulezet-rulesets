rule TTP_XOR_WriteProcessMemory_fa10 {
  strings:
    $key_fa10 = { ad 62 [2] 9f 40 [2] 99 75 [2] b7 75 [2] 88 69 }

  condition:
    any of them
}