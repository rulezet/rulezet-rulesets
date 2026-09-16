rule TTP_XOR_WriteProcessMemory_9db9 {
  strings:
    $key_9db9 = { ca cb [2] f8 e9 [2] fe dc [2] d0 dc [2] ef c0 }

  condition:
    any of them
}