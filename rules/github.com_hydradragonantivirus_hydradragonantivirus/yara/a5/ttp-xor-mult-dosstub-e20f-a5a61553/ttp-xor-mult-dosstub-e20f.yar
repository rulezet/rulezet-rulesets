rule TTP_XOR_MULT_DOSStub_e20f {
  strings:
    $key_e20f = { b6 67 [2] c2 7f [2] 85 7d [2] c2 6c [2] 8c 60 [2] 80 6a [2] 97 61 [2] 8c 2f [2] b1 }

  condition:
    any of them
}