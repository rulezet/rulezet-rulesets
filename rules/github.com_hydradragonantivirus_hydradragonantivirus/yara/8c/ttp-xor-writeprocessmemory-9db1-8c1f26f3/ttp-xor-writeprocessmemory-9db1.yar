rule TTP_XOR_WriteProcessMemory_9db1 {
  strings:
    $key_9db1 = { ca c3 [2] f8 e1 [2] fe d4 [2] d0 d4 [2] ef c8 }

  condition:
    any of them
}