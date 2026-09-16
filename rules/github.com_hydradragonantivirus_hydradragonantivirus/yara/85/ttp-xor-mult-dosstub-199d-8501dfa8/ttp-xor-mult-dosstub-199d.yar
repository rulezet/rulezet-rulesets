rule TTP_XOR_MULT_DOSStub_199d {
  strings:
    $key_199d = { 4d f5 [2] 39 ed [2] 7e ef [2] 39 fe [2] 77 f2 [2] 7b f8 [2] 6c f3 [2] 77 bd [2] 4a }

  condition:
    any of them
}