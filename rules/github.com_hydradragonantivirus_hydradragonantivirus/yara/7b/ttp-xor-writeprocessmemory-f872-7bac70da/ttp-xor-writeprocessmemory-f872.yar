rule TTP_XOR_WriteProcessMemory_f872 {
  strings:
    $key_f872 = { af 00 [2] 9d 22 [2] 9b 17 [2] b5 17 [2] 8a 0b }

  condition:
    any of them
}