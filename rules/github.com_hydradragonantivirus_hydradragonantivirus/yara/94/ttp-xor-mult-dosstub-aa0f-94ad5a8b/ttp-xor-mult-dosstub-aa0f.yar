rule TTP_XOR_MULT_DOSStub_aa0f {
  strings:
    $key_aa0f = { fe 67 [2] 8a 7f [2] cd 7d [2] 8a 6c [2] c4 60 [2] c8 6a [2] df 61 [2] c4 2f [2] f9 }

  condition:
    any of them
}