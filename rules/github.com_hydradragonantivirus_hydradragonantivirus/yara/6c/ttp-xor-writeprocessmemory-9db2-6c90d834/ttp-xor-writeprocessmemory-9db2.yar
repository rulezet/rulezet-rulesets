rule TTP_XOR_WriteProcessMemory_9db2 {
  strings:
    $key_9db2 = { ca c0 [2] f8 e2 [2] fe d7 [2] d0 d7 [2] ef cb }

  condition:
    any of them
}