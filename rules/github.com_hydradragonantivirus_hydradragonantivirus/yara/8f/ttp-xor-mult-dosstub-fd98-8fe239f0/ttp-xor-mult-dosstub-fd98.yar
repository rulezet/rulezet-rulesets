rule TTP_XOR_MULT_DOSStub_fd98 {
  strings:
    $key_fd98 = { a9 f0 [2] dd e8 [2] 9a ea [2] dd fb [2] 93 f7 [2] 9f fd [2] 88 f6 [2] 93 b8 [2] ae }

  condition:
    any of them
}