rule TTP_XOR_WriteProcessMemory_fa94 {
  strings:
    $key_fa94 = { ad e6 [2] 9f c4 [2] 99 f1 [2] b7 f1 [2] 88 ed }

  condition:
    any of them
}