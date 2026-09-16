rule TTP_XOR_WriteProcessMemory_b817 {
  strings:
    $key_b817 = { ef 65 [2] dd 47 [2] db 72 [2] f5 72 [2] ca 6e }

  condition:
    any of them
}