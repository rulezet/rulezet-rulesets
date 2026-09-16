rule TTP_XOR_MULT_DOSStub_a4ff {
  strings:
    $key_a4ff = { f0 97 [2] 84 8f [2] c3 8d [2] 84 9c [2] ca 90 [2] c6 9a [2] d1 91 [2] ca df [2] f7 }

  condition:
    any of them
}