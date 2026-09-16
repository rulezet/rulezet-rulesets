rule TTP_XOR_WriteProcessMemory_b833 {
  strings:
    $key_b833 = { ef 41 [2] dd 63 [2] db 56 [2] f5 56 [2] ca 4a }

  condition:
    any of them
}