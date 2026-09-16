rule TTP_XOR_MULT_DOSStub_fdda {
  strings:
    $key_fdda = { a9 b2 [2] dd aa [2] 9a a8 [2] dd b9 [2] 93 b5 [2] 9f bf [2] 88 b4 [2] 93 fa [2] ae }

  condition:
    any of them
}