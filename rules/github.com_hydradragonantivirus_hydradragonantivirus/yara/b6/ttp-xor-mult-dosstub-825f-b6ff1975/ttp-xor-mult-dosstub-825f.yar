rule TTP_XOR_MULT_DOSStub_825f {
  strings:
    $key_825f = { d6 37 [2] a2 2f [2] e5 2d [2] a2 3c [2] ec 30 [2] e0 3a [2] f7 31 [2] ec 7f [2] d1 }

  condition:
    any of them
}