rule TTP_XOR_MULT_DOSStub_ed75 {
  strings:
    $key_ed75 = { b9 1d [2] cd 05 [2] 8a 07 [2] cd 16 [2] 83 1a [2] 8f 10 [2] 98 1b [2] 83 55 [2] be }

  condition:
    any of them
}