rule TTP_XOR_MULT_DOSStub_db80 {
  strings:
    $key_db80 = { 8f e8 [2] fb f0 [2] bc f2 [2] fb e3 [2] b5 ef [2] b9 e5 [2] ae ee [2] b5 a0 [2] 88 }

  condition:
    any of them
}