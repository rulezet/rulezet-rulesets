rule TTP_XOR_WriteProcessMemory_0465 {
  strings:
    $key_0465 = { 53 17 [2] 61 35 [2] 67 00 [2] 49 00 [2] 76 1c }

  condition:
    any of them
}