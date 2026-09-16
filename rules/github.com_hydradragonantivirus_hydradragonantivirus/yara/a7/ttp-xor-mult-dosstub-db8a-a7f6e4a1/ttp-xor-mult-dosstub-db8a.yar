rule TTP_XOR_MULT_DOSStub_db8a {
  strings:
    $key_db8a = { 8f e2 [2] fb fa [2] bc f8 [2] fb e9 [2] b5 e5 [2] b9 ef [2] ae e4 [2] b5 aa [2] 88 }

  condition:
    any of them
}