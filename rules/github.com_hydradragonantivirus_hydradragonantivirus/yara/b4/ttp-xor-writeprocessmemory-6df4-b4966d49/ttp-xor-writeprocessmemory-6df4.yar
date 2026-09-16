rule TTP_XOR_WriteProcessMemory_6df4 {
  strings:
    $key_6df4 = { 3a 86 [2] 08 a4 [2] 0e 91 [2] 20 91 [2] 1f 8d }

  condition:
    any of them
}