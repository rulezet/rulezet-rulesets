rule TTP_XOR_WriteProcessMemory_3293 {
  strings:
    $key_3293 = { 65 e1 [2] 57 c3 [2] 51 f6 [2] 7f f6 [2] 40 ea }

  condition:
    any of them
}