rule TTP_XOR_WriteProcessMemory_9db4 {
  strings:
    $key_9db4 = { ca c6 [2] f8 e4 [2] fe d1 [2] d0 d1 [2] ef cd }

  condition:
    any of them
}