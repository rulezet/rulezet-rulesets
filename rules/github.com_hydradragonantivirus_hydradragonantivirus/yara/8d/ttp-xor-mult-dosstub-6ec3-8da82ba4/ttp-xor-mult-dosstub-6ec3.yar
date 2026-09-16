rule TTP_XOR_MULT_DOSStub_6ec3 {
  strings:
    $key_6ec3 = { 3a ab [2] 4e b3 [2] 09 b1 [2] 4e a0 [2] 00 ac [2] 0c a6 [2] 1b ad [2] 00 e3 [2] 3d }

  condition:
    any of them
}