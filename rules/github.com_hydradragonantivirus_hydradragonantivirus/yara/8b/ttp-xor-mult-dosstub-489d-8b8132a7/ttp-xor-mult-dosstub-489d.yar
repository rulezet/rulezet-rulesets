rule TTP_XOR_MULT_DOSStub_489d {
  strings:
    $key_489d = { 1c f5 [2] 68 ed [2] 2f ef [2] 68 fe [2] 26 f2 [2] 2a f8 [2] 3d f3 [2] 26 bd [2] 1b }

  condition:
    any of them
}