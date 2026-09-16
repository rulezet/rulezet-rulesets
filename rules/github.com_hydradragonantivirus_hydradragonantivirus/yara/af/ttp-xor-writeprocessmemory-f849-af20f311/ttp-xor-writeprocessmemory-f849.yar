rule TTP_XOR_WriteProcessMemory_f849 {
  strings:
    $key_f849 = { af 3b [2] 9d 19 [2] 9b 2c [2] b5 2c [2] 8a 30 }

  condition:
    any of them
}