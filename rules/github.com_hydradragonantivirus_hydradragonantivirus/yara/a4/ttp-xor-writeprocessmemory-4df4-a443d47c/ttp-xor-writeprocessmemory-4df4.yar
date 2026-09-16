rule TTP_XOR_WriteProcessMemory_4df4 {
  strings:
    $key_4df4 = { 1a 86 [2] 28 a4 [2] 2e 91 [2] 00 91 [2] 3f 8d }

  condition:
    any of them
}