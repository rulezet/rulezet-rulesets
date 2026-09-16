rule TTP_XOR_WriteProcessMemory_fa90 {
  strings:
    $key_fa90 = { ad e2 [2] 9f c0 [2] 99 f5 [2] b7 f5 [2] 88 e9 }

  condition:
    any of them
}