rule TTP_XOR_MULT_DOSStub_da6f {
  strings:
    $key_da6f = { 8e 07 [2] fa 1f [2] bd 1d [2] fa 0c [2] b4 00 [2] b8 0a [2] af 01 [2] b4 4f [2] 89 }

  condition:
    any of them
}