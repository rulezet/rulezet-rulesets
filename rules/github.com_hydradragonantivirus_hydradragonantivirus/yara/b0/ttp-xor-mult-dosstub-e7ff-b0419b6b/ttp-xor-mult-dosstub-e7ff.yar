rule TTP_XOR_MULT_DOSStub_e7ff {
  strings:
    $key_e7ff = { b3 97 [2] c7 8f [2] 80 8d [2] c7 9c [2] 89 90 [2] 85 9a [2] 92 91 [2] 89 df [2] b4 }

  condition:
    any of them
}