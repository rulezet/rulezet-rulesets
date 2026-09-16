rule TTP_XOR_WriteProcessMemory_b834 {
  strings:
    $key_b834 = { ef 46 [2] dd 64 [2] db 51 [2] f5 51 [2] ca 4d }

  condition:
    any of them
}