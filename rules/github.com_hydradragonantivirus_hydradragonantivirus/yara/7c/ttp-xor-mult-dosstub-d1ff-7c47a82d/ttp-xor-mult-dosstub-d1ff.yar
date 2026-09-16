rule TTP_XOR_MULT_DOSStub_d1ff {
  strings:
    $key_d1ff = { 85 97 [2] f1 8f [2] b6 8d [2] f1 9c [2] bf 90 [2] b3 9a [2] a4 91 [2] bf df [2] 82 }

  condition:
    any of them
}