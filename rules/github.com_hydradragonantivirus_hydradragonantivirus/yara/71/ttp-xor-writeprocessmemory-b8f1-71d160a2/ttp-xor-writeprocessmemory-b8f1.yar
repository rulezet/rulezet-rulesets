rule TTP_XOR_WriteProcessMemory_b8f1 {
  strings:
    $key_b8f1 = { ef 83 [2] dd a1 [2] db 94 [2] f5 94 [2] ca 88 }

  condition:
    any of them
}