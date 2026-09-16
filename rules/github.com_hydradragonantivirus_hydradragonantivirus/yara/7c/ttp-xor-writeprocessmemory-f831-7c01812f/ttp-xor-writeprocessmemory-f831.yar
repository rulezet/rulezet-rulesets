rule TTP_XOR_WriteProcessMemory_f831 {
  strings:
    $key_f831 = { af 43 [2] 9d 61 [2] 9b 54 [2] b5 54 [2] 8a 48 }

  condition:
    any of them
}