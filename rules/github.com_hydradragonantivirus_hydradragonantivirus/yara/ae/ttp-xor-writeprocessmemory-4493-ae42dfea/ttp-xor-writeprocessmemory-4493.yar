rule TTP_XOR_WriteProcessMemory_4493 {
  strings:
    $key_4493 = { 13 e1 [2] 21 c3 [2] 27 f6 [2] 09 f6 [2] 36 ea }

  condition:
    any of them
}