rule TTP_XOR_WriteProcessMemory_0393 {
  strings:
    $key_0393 = { 54 e1 [2] 66 c3 [2] 60 f6 [2] 4e f6 [2] 71 ea }

  condition:
    any of them
}