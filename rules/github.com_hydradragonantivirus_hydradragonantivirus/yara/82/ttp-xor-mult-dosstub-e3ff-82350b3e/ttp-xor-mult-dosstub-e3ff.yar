rule TTP_XOR_MULT_DOSStub_e3ff {
  strings:
    $key_e3ff = { b7 97 [2] c3 8f [2] 84 8d [2] c3 9c [2] 8d 90 [2] 81 9a [2] 96 91 [2] 8d df [2] b0 }

  condition:
    any of them
}