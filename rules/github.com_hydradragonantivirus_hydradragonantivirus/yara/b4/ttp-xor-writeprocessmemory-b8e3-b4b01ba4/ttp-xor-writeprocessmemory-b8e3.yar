rule TTP_XOR_WriteProcessMemory_b8e3 {
  strings:
    $key_b8e3 = { ef 91 [2] dd b3 [2] db 86 [2] f5 86 [2] ca 9a }

  condition:
    any of them
}