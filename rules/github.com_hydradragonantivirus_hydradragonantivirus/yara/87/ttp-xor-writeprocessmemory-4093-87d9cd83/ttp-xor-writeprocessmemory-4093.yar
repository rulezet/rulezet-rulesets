rule TTP_XOR_WriteProcessMemory_4093 {
  strings:
    $key_4093 = { 17 e1 [2] 25 c3 [2] 23 f6 [2] 0d f6 [2] 32 ea }

  condition:
    any of them
}