rule TTP_XOR_WriteProcessMemory_0793 {
  strings:
    $key_0793 = { 50 e1 [2] 62 c3 [2] 64 f6 [2] 4a f6 [2] 75 ea }

  condition:
    any of them
}