rule TTP_XOR_WriteProcessMemory_c857 {
  strings:
    $key_c857 = { 9f 25 [2] ad 07 [2] ab 32 [2] 85 32 [2] ba 2e }

  condition:
    any of them
}