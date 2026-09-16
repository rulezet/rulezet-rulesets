rule TTP_XOR_WriteProcessMemory_e6f4 {
  strings:
    $key_e6f4 = { b1 86 [2] 83 a4 [2] 85 91 [2] ab 91 [2] 94 8d }

  condition:
    any of them
}