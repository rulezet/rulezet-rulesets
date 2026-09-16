rule TTP_XOR_MULT_DOSStub_399d {
  strings:
    $key_399d = { 6d f5 [2] 19 ed [2] 5e ef [2] 19 fe [2] 57 f2 [2] 5b f8 [2] 4c f3 [2] 57 bd [2] 6a }

  condition:
    any of them
}