rule TTP_XOR_WriteProcessMemory_e396 {
  strings:
    $key_e396 = { b4 e4 [2] 86 c6 [2] 80 f3 [2] ae f3 [2] 91 ef }

  condition:
    any of them
}