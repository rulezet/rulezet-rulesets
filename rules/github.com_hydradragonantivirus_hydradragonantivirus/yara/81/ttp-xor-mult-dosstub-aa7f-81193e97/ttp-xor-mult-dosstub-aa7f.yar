rule TTP_XOR_MULT_DOSStub_aa7f {
  strings:
    $key_aa7f = { fe 17 [2] 8a 0f [2] cd 0d [2] 8a 1c [2] c4 10 [2] c8 1a [2] df 11 [2] c4 5f [2] f9 }

  condition:
    any of them
}