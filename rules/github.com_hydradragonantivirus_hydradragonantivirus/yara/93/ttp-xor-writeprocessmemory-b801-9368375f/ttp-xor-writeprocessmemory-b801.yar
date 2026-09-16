rule TTP_XOR_WriteProcessMemory_b801 {
  strings:
    $key_b801 = { ef 73 [2] dd 51 [2] db 64 [2] f5 64 [2] ca 78 }

  condition:
    any of them
}