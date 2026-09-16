rule TTP_XOR_WriteProcessMemory_f816 {
  strings:
    $key_f816 = { af 64 [2] 9d 46 [2] 9b 73 [2] b5 73 [2] 8a 6f }

  condition:
    any of them
}