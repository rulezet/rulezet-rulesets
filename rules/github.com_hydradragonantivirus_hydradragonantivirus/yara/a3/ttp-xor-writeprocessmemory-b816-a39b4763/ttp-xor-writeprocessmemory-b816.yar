rule TTP_XOR_WriteProcessMemory_b816 {
  strings:
    $key_b816 = { ef 64 [2] dd 46 [2] db 73 [2] f5 73 [2] ca 6f }

  condition:
    any of them
}