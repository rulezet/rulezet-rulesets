rule TTP_XOR_MULT_DOSStub_e0ff {
  strings:
    $key_e0ff = { b4 97 [2] c0 8f [2] 87 8d [2] c0 9c [2] 8e 90 [2] 82 9a [2] 95 91 [2] 8e df [2] b3 }

  condition:
    any of them
}