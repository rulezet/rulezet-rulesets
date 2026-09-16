rule TTP_XOR_MULT_DOSStub_6fc5 {
  strings:
    $key_6fc5 = { 3b ad [2] 4f b5 [2] 08 b7 [2] 4f a6 [2] 01 aa [2] 0d a0 [2] 1a ab [2] 01 e5 [2] 3c }

  condition:
    any of them
}