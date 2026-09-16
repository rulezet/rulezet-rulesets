rule TTP_XOR_WriteProcessMemory_b8f7 {
  strings:
    $key_b8f7 = { ef 85 [2] dd a7 [2] db 92 [2] f5 92 [2] ca 8e }

  condition:
    any of them
}