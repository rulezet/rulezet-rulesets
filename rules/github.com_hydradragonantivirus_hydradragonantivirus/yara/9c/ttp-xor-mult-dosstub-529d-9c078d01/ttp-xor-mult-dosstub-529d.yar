rule TTP_XOR_MULT_DOSStub_529d {
  strings:
    $key_529d = { 06 f5 [2] 72 ed [2] 35 ef [2] 72 fe [2] 3c f2 [2] 30 f8 [2] 27 f3 [2] 3c bd [2] 01 }

  condition:
    any of them
}