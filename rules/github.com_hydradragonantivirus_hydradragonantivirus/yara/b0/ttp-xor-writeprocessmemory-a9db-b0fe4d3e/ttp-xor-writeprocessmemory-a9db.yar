rule TTP_XOR_WriteProcessMemory_a9db {
  strings:
    $key_a9db = { fe a9 [2] cc 8b [2] ca be [2] e4 be [2] db a2 }

  condition:
    any of them
}