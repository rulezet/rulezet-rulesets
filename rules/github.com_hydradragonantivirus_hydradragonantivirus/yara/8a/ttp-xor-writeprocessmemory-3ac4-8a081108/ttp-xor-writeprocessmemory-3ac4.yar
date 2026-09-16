rule TTP_XOR_WriteProcessMemory_3ac4 {
  strings:
    $key_3ac4 = { 6d b6 [2] 5f 94 [2] 59 a1 [2] 77 a1 [2] 48 bd }

  condition:
    any of them
}