rule TTP_XOR_MULT_DOSStub_c4ff {
  strings:
    $key_c4ff = { 90 97 [2] e4 8f [2] a3 8d [2] e4 9c [2] aa 90 [2] a6 9a [2] b1 91 [2] aa df [2] 97 }

  condition:
    any of them
}