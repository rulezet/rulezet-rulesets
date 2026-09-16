rule TTP_XOR_MULT_DOSStub_910f {
  strings:
    $key_910f = { c5 67 [2] b1 7f [2] f6 7d [2] b1 6c [2] ff 60 [2] f3 6a [2] e4 61 [2] ff 2f [2] c2 }

  condition:
    any of them
}