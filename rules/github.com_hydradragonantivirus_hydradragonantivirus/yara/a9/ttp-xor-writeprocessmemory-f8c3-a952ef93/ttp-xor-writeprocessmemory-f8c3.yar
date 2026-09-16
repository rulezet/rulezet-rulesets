rule TTP_XOR_WriteProcessMemory_f8c3 {
  strings:
    $key_f8c3 = { af b1 [2] 9d 93 [2] 9b a6 [2] b5 a6 [2] 8a ba }

  condition:
    any of them
}