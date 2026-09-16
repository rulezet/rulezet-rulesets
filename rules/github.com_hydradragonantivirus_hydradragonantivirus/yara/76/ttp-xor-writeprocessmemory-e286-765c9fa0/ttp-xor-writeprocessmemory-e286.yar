rule TTP_XOR_WriteProcessMemory_e286 {
  strings:
    $key_e286 = { b5 f4 [2] 87 d6 [2] 81 e3 [2] af e3 [2] 90 ff }

  condition:
    any of them
}