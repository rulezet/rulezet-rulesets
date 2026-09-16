rule TTP_XOR_WriteProcessMemory_b878 {
  strings:
    $key_b878 = { ef 0a [2] dd 28 [2] db 1d [2] f5 1d [2] ca 01 }

  condition:
    any of them
}