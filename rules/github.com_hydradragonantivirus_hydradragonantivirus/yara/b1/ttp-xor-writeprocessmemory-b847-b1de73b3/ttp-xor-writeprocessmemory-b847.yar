rule TTP_XOR_WriteProcessMemory_b847 {
  strings:
    $key_b847 = { ef 35 [2] dd 17 [2] db 22 [2] f5 22 [2] ca 3e }

  condition:
    any of them
}