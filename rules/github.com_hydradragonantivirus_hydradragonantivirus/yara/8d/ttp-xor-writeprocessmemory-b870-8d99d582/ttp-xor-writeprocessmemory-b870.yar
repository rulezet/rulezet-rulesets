rule TTP_XOR_WriteProcessMemory_b870 {
  strings:
    $key_b870 = { ef 02 [2] dd 20 [2] db 15 [2] f5 15 [2] ca 09 }

  condition:
    any of them
}