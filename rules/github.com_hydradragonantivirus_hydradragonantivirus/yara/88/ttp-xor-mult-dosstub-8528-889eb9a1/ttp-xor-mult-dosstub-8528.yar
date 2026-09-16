rule TTP_XOR_MULT_DOSStub_8528 {
  strings:
    $key_8528 = { d1 40 [2] a5 58 [2] e2 5a [2] a5 4b [2] eb 47 [2] e7 4d [2] f0 46 [2] eb 08 [2] d6 }

  condition:
    any of them
}