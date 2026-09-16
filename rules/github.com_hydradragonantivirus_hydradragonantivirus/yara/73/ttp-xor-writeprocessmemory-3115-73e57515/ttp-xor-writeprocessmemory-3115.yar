rule TTP_XOR_WriteProcessMemory_3115 {
  strings:
    $key_3115 = { 66 67 [2] 54 45 [2] 52 70 [2] 7c 70 [2] 43 6c }

  condition:
    any of them
}