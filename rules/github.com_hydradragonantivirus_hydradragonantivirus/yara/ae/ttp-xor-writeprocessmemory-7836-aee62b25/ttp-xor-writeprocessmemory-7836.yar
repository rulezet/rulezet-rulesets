rule TTP_XOR_WriteProcessMemory_7836 {
  strings:
    $key_7836 = { 2f 44 [2] 1d 66 [2] 1b 53 [2] 35 53 [2] 0a 4f }

  condition:
    any of them
}