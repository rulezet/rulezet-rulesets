rule TTP_XOR_WriteProcessMemory_5df4 {
  strings:
    $key_5df4 = { 0a 86 [2] 38 a4 [2] 3e 91 [2] 10 91 [2] 2f 8d }

  condition:
    any of them
}