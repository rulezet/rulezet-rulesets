rule TTP_XOR_WriteProcessMemory_f853 {
  strings:
    $key_f853 = { af 21 [2] 9d 03 [2] 9b 36 [2] b5 36 [2] 8a 2a }

  condition:
    any of them
}