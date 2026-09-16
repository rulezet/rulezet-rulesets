rule TTP_XOR_MULT_DOSStub_d0ff {
  strings:
    $key_d0ff = { 84 97 [2] f0 8f [2] b7 8d [2] f0 9c [2] be 90 [2] b2 9a [2] a5 91 [2] be df [2] 83 }

  condition:
    any of them
}