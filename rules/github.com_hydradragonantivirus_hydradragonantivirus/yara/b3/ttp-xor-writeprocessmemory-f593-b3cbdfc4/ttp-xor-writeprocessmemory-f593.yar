rule TTP_XOR_WriteProcessMemory_f593 {
  strings:
    $key_f593 = { a2 e1 [2] 90 c3 [2] 96 f6 [2] b8 f6 [2] 87 ea }

  condition:
    any of them
}