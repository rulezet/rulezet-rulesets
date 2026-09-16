rule TTP_XOR_WriteProcessMemory_e9f4 {
  strings:
    $key_e9f4 = { be 86 [2] 8c a4 [2] 8a 91 [2] a4 91 [2] 9b 8d }

  condition:
    any of them
}