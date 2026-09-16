rule TTP_XOR_WriteProcessMemory_b824 {
  strings:
    $key_b824 = { ef 56 [2] dd 74 [2] db 41 [2] f5 41 [2] ca 5d }

  condition:
    any of them
}