rule TTP_XOR_WriteProcessMemory_f860 {
  strings:
    $key_f860 = { af 12 [2] 9d 30 [2] 9b 05 [2] b5 05 [2] 8a 19 }

  condition:
    any of them
}