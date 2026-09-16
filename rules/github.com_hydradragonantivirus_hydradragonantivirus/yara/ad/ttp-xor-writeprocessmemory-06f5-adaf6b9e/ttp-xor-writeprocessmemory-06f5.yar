rule TTP_XOR_WriteProcessMemory_06f5 {
  strings:
    $key_06f5 = { 51 87 [2] 63 a5 [2] 65 90 [2] 4b 90 [2] 74 8c }

  condition:
    any of them
}