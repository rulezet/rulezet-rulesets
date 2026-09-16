rule TTP_XOR_MULT_DOSStub_da09 {
  strings:
    $key_da09 = { 8e 61 [2] fa 79 [2] bd 7b [2] fa 6a [2] b4 66 [2] b8 6c [2] af 67 [2] b4 29 [2] 89 }

  condition:
    any of them
}