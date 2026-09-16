rule TTP_XOR_WriteProcessMemory_30f4 {
  strings:
    $key_30f4 = { 67 86 [2] 55 a4 [2] 53 91 [2] 7d 91 [2] 42 8d }

  condition:
    any of them
}