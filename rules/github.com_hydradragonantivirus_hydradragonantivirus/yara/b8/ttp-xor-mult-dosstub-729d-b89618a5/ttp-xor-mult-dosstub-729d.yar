rule TTP_XOR_MULT_DOSStub_729d {
  strings:
    $key_729d = { 26 f5 [2] 52 ed [2] 15 ef [2] 52 fe [2] 1c f2 [2] 10 f8 [2] 07 f3 [2] 1c bd [2] 21 }

  condition:
    any of them
}