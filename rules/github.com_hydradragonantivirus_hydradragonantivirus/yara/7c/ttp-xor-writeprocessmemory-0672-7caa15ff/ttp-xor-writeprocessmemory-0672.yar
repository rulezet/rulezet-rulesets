rule TTP_XOR_WriteProcessMemory_0672 {
  strings:
    $key_0672 = { 51 00 [2] 63 22 [2] 65 17 [2] 4b 17 [2] 74 0b }

  condition:
    any of them
}