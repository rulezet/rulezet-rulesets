rule TTP_XOR_MULT_DOSStub_d7ff {
  strings:
    $key_d7ff = { 83 97 [2] f7 8f [2] b0 8d [2] f7 9c [2] b9 90 [2] b5 9a [2] a2 91 [2] b9 df [2] 84 }

  condition:
    any of them
}