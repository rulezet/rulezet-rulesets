rule TTP_XOR_WriteProcessMemory_f876 {
  strings:
    $key_f876 = { af 04 [2] 9d 26 [2] 9b 13 [2] b5 13 [2] 8a 0f }

  condition:
    any of them
}