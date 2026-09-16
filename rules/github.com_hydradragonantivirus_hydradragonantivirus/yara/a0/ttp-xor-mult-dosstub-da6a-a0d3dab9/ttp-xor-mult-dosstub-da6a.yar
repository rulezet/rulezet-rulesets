rule TTP_XOR_MULT_DOSStub_da6a {
  strings:
    $key_da6a = { 8e 02 [2] fa 1a [2] bd 18 [2] fa 09 [2] b4 05 [2] b8 0f [2] af 04 [2] b4 4a [2] 89 }

  condition:
    any of them
}