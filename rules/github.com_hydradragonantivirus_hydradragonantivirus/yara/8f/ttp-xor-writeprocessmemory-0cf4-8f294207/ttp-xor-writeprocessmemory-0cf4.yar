rule TTP_XOR_WriteProcessMemory_0cf4 {
  strings:
    $key_0cf4 = { 5b 86 [2] 69 a4 [2] 6f 91 [2] 41 91 [2] 7e 8d }

  condition:
    any of them
}