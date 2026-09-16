rule TTP_XOR_WriteProcessMemory_fa48 {
  strings:
    $key_fa48 = { ad 3a [2] 9f 18 [2] 99 2d [2] b7 2d [2] 88 31 }

  condition:
    any of them
}