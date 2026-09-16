rule TTP_XOR_WriteProcessMemory_f800 {
  strings:
    $key_f800 = { af 72 [2] 9d 50 [2] 9b 65 [2] b5 65 [2] 8a 79 }

  condition:
    any of them
}