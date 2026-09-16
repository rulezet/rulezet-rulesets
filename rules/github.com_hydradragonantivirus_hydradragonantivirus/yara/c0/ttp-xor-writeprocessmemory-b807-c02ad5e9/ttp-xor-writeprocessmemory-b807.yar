rule TTP_XOR_WriteProcessMemory_b807 {
  strings:
    $key_b807 = { ef 75 [2] dd 57 [2] db 62 [2] f5 62 [2] ca 7e }

  condition:
    any of them
}