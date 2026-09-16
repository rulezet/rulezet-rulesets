rule TTP_XOR_WriteProcessMemory_b8f5 {
  strings:
    $key_b8f5 = { ef 87 [2] dd a5 [2] db 90 [2] f5 90 [2] ca 8c }

  condition:
    any of them
}