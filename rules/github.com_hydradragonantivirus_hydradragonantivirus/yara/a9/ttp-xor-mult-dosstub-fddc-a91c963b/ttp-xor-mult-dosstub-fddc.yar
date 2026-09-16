rule TTP_XOR_MULT_DOSStub_fddc {
  strings:
    $key_fddc = { a9 b4 [2] dd ac [2] 9a ae [2] dd bf [2] 93 b3 [2] 9f b9 [2] 88 b2 [2] 93 fc [2] ae }

  condition:
    any of them
}