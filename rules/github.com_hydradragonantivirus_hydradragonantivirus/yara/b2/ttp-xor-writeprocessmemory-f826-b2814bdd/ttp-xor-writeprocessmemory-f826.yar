rule TTP_XOR_WriteProcessMemory_f826 {
  strings:
    $key_f826 = { af 54 [2] 9d 76 [2] 9b 43 [2] b5 43 [2] 8a 5f }

  condition:
    any of them
}