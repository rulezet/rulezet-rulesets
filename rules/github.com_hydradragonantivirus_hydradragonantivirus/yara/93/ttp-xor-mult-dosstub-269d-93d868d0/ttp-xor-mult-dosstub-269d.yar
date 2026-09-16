rule TTP_XOR_MULT_DOSStub_269d {
  strings:
    $key_269d = { 72 f5 [2] 06 ed [2] 41 ef [2] 06 fe [2] 48 f2 [2] 44 f8 [2] 53 f3 [2] 48 bd [2] 75 }

  condition:
    any of them
}