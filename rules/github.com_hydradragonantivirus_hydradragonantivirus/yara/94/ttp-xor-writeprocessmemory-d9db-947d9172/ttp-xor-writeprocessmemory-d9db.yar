rule TTP_XOR_WriteProcessMemory_d9db {
  strings:
    $key_d9db = { 8e a9 [2] bc 8b [2] ba be [2] 94 be [2] ab a2 }

  condition:
    any of them
}