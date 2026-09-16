rule TTP_XOR_MULT_DOSStub_2fc5 {
  strings:
    $key_2fc5 = { 7b ad [2] 0f b5 [2] 48 b7 [2] 0f a6 [2] 41 aa [2] 4d a0 [2] 5a ab [2] 41 e5 [2] 7c }

  condition:
    any of them
}