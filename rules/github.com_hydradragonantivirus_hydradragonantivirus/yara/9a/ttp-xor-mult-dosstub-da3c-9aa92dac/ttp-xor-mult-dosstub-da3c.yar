rule TTP_XOR_MULT_DOSStub_da3c {
  strings:
    $key_da3c = { 8e 54 [2] fa 4c [2] bd 4e [2] fa 5f [2] b4 53 [2] b8 59 [2] af 52 [2] b4 1c [2] 89 }

  condition:
    any of them
}