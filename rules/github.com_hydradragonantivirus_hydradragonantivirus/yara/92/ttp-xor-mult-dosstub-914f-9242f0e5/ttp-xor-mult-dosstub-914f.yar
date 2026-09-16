rule TTP_XOR_MULT_DOSStub_914f {
  strings:
    $key_914f = { c5 27 [2] b1 3f [2] f6 3d [2] b1 2c [2] ff 20 [2] f3 2a [2] e4 21 [2] ff 6f [2] c2 }

  condition:
    any of them
}