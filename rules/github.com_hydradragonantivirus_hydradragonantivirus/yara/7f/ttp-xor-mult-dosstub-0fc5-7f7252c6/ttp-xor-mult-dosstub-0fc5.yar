rule TTP_XOR_MULT_DOSStub_0fc5 {
  strings:
    $key_0fc5 = { 5b ad [2] 2f b5 [2] 68 b7 [2] 2f a6 [2] 61 aa [2] 6d a0 [2] 7a ab [2] 61 e5 [2] 5c }

  condition:
    any of them
}