rule TTP_XOR_MULT_DOSStub_c80e {
  strings:
    $key_c80e = { 9c 66 [2] e8 7e [2] af 7c [2] e8 6d [2] a6 61 [2] aa 6b [2] bd 60 [2] a6 2e [2] 9b }

  condition:
    any of them
}