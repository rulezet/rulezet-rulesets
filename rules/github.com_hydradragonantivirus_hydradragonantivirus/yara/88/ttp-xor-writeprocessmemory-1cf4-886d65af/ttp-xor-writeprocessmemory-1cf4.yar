rule TTP_XOR_WriteProcessMemory_1cf4 {
  strings:
    $key_1cf4 = { 4b 86 [2] 79 a4 [2] 7f 91 [2] 51 91 [2] 6e 8d }

  condition:
    any of them
}