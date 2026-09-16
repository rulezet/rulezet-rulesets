rule TTP_XOR_WriteProcessMemory_e397 {
  strings:
    $key_e397 = { b4 e5 [2] 86 c7 [2] 80 f2 [2] ae f2 [2] 91 ee }

  condition:
    any of them
}