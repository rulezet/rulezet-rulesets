rule TTP_XOR_MULT_DOSStub_853b {
  strings:
    $key_853b = { d1 53 [2] a5 4b [2] e2 49 [2] a5 58 [2] eb 54 [2] e7 5e [2] f0 55 [2] eb 1b [2] d6 }

  condition:
    any of them
}