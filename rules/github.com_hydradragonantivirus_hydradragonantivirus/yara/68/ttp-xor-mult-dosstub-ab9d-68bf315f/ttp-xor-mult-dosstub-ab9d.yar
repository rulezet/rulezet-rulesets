rule TTP_XOR_MULT_DOSStub_ab9d {
  strings:
    $key_ab9d = { ff f5 [2] 8b ed [2] cc ef [2] 8b fe [2] c5 f2 [2] c9 f8 [2] de f3 [2] c5 bd [2] f8 }

  condition:
    any of them
}