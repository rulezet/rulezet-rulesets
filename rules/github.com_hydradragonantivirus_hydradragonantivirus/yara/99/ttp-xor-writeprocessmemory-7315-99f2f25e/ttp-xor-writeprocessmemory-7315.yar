rule TTP_XOR_WriteProcessMemory_7315 {
  strings:
    $key_7315 = { 24 67 [2] 16 45 [2] 10 70 [2] 3e 70 [2] 01 6c }

  condition:
    any of them
}