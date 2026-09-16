rule TTP_XOR_WriteProcessMemory_3df4 {
  strings:
    $key_3df4 = { 6a 86 [2] 58 a4 [2] 5e 91 [2] 70 91 [2] 4f 8d }

  condition:
    any of them
}