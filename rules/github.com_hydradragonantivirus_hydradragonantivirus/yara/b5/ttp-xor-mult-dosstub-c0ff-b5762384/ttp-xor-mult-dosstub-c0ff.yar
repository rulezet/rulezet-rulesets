rule TTP_XOR_MULT_DOSStub_c0ff {
  strings:
    $key_c0ff = { 94 97 [2] e0 8f [2] a7 8d [2] e0 9c [2] ae 90 [2] a2 9a [2] b5 91 [2] ae df [2] 93 }

  condition:
    any of them
}