rule TTP_XOR_WriteProcessMemory_1df4 {
  strings:
    $key_1df4 = { 4a 86 [2] 78 a4 [2] 7e 91 [2] 50 91 [2] 6f 8d }

  condition:
    any of them
}