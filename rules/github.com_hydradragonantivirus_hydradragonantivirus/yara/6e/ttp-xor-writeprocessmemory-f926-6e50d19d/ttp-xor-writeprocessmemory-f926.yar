rule TTP_XOR_WriteProcessMemory_f926 {
  strings:
    $key_f926 = { ae 54 [2] 9c 76 [2] 9a 43 [2] b4 43 [2] 8b 5f }

  condition:
    any of them
}