rule TTP_XOR_WriteProcessMemory_c9db {
  strings:
    $key_c9db = { 9e a9 [2] ac 8b [2] aa be [2] 84 be [2] bb a2 }

  condition:
    any of them
}