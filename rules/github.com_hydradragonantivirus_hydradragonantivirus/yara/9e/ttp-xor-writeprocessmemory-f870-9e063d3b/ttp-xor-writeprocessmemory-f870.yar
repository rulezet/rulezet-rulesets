rule TTP_XOR_WriteProcessMemory_f870 {
  strings:
    $key_f870 = { af 02 [2] 9d 20 [2] 9b 15 [2] b5 15 [2] 8a 09 }

  condition:
    any of them
}