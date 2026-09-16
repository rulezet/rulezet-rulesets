rule TTP_XOR_WriteProcessMemory_b831 {
  strings:
    $key_b831 = { ef 43 [2] dd 61 [2] db 54 [2] f5 54 [2] ca 48 }

  condition:
    any of them
}