rule TTP_XOR_WriteProcessMemory_f579 {
  strings:
    $key_f579 = { a2 0b [2] 90 29 [2] 96 1c [2] b8 1c [2] 87 00 }

  condition:
    any of them
}