rule TTP_XOR_WriteProcessMemory_b8fe {
  strings:
    $key_b8fe = { ef 8c [2] dd ae [2] db 9b [2] f5 9b [2] ca 87 }

  condition:
    any of them
}