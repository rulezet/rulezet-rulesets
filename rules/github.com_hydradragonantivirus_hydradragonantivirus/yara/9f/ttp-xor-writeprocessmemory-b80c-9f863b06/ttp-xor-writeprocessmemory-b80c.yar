rule TTP_XOR_WriteProcessMemory_b80c {
  strings:
    $key_b80c = { ef 7e [2] dd 5c [2] db 69 [2] f5 69 [2] ca 75 }

  condition:
    any of them
}