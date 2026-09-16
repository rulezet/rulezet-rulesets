rule TTP_XOR_WriteProcessMemory_f836 {
  strings:
    $key_f836 = { af 44 [2] 9d 66 [2] 9b 53 [2] b5 53 [2] 8a 4f }

  condition:
    any of them
}