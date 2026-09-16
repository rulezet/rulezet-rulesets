rule TTP_XOR_WriteProcessMemory_3082 {
  strings:
    $key_3082 = { 67 f0 [2] 55 d2 [2] 53 e7 [2] 7d e7 [2] 42 fb }

  condition:
    any of them
}