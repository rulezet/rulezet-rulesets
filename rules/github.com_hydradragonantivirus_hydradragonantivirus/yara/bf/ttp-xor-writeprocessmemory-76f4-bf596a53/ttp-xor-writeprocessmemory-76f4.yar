rule TTP_XOR_WriteProcessMemory_76f4 {
  strings:
    $key_76f4 = { 21 86 [2] 13 a4 [2] 15 91 [2] 3b 91 [2] 04 8d }

  condition:
    any of them
}