rule TTP_XOR_MULT_DOSStub_c2ff {
  strings:
    $key_c2ff = { 96 97 [2] e2 8f [2] a5 8d [2] e2 9c [2] ac 90 [2] a0 9a [2] b7 91 [2] ac df [2] 91 }

  condition:
    any of them
}