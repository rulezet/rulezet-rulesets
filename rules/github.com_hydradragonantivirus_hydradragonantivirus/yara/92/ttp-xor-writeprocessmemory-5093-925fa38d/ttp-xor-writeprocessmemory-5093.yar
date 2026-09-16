rule TTP_XOR_WriteProcessMemory_5093 {
  strings:
    $key_5093 = { 07 e1 [2] 35 c3 [2] 33 f6 [2] 1d f6 [2] 22 ea }

  condition:
    any of them
}