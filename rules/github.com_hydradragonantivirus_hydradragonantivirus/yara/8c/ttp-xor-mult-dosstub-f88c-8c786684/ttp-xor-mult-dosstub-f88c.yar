rule TTP_XOR_MULT_DOSStub_f88c {
  strings:
    $key_f88c = { ac e4 [2] d8 fc [2] 9f fe [2] d8 ef [2] 96 e3 [2] 9a e9 [2] 8d e2 [2] 96 ac [2] ab }

  condition:
    any of them
}