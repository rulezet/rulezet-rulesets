rule TTP_XOR_MULT_DOSStub_fd8c {
  strings:
    $key_fd8c = { a9 e4 [2] dd fc [2] 9a fe [2] dd ef [2] 93 e3 [2] 9f e9 [2] 88 e2 [2] 93 ac [2] ae }

  condition:
    any of them
}