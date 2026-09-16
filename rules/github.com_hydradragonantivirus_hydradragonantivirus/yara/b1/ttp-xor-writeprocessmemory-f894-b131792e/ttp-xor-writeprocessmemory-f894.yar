rule TTP_XOR_WriteProcessMemory_f894 {
  strings:
    $key_f894 = { af e6 [2] 9d c4 [2] 9b f1 [2] b5 f1 [2] 8a ed }

  condition:
    any of them
}