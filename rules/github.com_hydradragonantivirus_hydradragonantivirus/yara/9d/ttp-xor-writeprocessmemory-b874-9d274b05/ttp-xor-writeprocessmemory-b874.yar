rule TTP_XOR_WriteProcessMemory_b874 {
  strings:
    $key_b874 = { ef 06 [2] dd 24 [2] db 11 [2] f5 11 [2] ca 0d }

  condition:
    any of them
}