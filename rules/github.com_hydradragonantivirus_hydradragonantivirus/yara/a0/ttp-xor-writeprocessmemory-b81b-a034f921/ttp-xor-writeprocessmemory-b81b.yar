rule TTP_XOR_WriteProcessMemory_b81b {
  strings:
    $key_b81b = { ef 69 [2] dd 4b [2] db 7e [2] f5 7e [2] ca 62 }

  condition:
    any of them
}