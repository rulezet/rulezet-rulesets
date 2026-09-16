rule TTP_XOR_MULT_DOSStub_850f {
  strings:
    $key_850f = { d1 67 [2] a5 7f [2] e2 7d [2] a5 6c [2] eb 60 [2] e7 6a [2] f0 61 [2] eb 2f [2] d6 }

  condition:
    any of them
}