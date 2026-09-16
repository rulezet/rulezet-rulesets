rule TTP_XOR_MULT_DOSStub_aa6f {
  strings:
    $key_aa6f = { fe 07 [2] 8a 1f [2] cd 1d [2] 8a 0c [2] c4 00 [2] c8 0a [2] df 01 [2] c4 4f [2] f9 }

  condition:
    any of them
}