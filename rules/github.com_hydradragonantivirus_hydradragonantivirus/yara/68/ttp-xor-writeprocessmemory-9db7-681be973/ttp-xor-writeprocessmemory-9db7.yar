rule TTP_XOR_WriteProcessMemory_9db7 {
  strings:
    $key_9db7 = { ca c5 [2] f8 e7 [2] fe d2 [2] d0 d2 [2] ef ce }

  condition:
    any of them
}