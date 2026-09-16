rule TTP_XOR_MULT_DOSStub_ff9d {
  strings:
    $key_ff9d = { ab f5 [2] df ed [2] 98 ef [2] df fe [2] 91 f2 [2] 9d f8 [2] 8a f3 [2] 91 bd [2] ac }

  condition:
    any of them
}