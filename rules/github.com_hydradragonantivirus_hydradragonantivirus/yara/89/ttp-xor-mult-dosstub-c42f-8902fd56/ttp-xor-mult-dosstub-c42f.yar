rule TTP_XOR_MULT_DOSStub_c42f {
  strings:
    $key_c42f = { 90 47 [2] e4 5f [2] a3 5d [2] e4 4c [2] aa 40 [2] a6 4a [2] b1 41 [2] aa 0f [2] 97 }

  condition:
    any of them
}