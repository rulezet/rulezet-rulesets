rule TTP_XOR_WriteProcessMemory_b87a {
  strings:
    $key_b87a = { ef 08 [2] dd 2a [2] db 1f [2] f5 1f [2] ca 03 }

  condition:
    any of them
}