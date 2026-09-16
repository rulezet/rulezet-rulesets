rule TTP_XOR_MULT_DOSStub_5fc5 {
  strings:
    $key_5fc5 = { 0b ad [2] 7f b5 [2] 38 b7 [2] 7f a6 [2] 31 aa [2] 3d a0 [2] 2a ab [2] 31 e5 [2] 0c }

  condition:
    any of them
}