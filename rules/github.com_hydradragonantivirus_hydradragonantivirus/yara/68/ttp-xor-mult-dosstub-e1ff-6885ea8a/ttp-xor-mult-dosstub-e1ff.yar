rule TTP_XOR_MULT_DOSStub_e1ff {
  strings:
    $key_e1ff = { b5 97 [2] c1 8f [2] 86 8d [2] c1 9c [2] 8f 90 [2] 83 9a [2] 94 91 [2] 8f df [2] b2 }

  condition:
    any of them
}