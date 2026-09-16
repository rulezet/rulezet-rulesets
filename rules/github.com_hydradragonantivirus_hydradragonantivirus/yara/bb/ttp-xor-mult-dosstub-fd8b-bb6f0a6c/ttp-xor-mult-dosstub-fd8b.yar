rule TTP_XOR_MULT_DOSStub_fd8b {
  strings:
    $key_fd8b = { a9 e3 [2] dd fb [2] 9a f9 [2] dd e8 [2] 93 e4 [2] 9f ee [2] 88 e5 [2] 93 ab [2] ae }

  condition:
    any of them
}