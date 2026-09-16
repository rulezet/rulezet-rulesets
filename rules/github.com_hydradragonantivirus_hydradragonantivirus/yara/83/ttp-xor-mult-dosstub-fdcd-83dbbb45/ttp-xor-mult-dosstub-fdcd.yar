rule TTP_XOR_MULT_DOSStub_fdcd {
  strings:
    $key_fdcd = { a9 a5 [2] dd bd [2] 9a bf [2] dd ae [2] 93 a2 [2] 9f a8 [2] 88 a3 [2] 93 ed [2] ae }

  condition:
    any of them
}