rule TTP_XOR_MULT_DOSStub_ed35 {
  strings:
    $key_ed35 = { b9 5d [2] cd 45 [2] 8a 47 [2] cd 56 [2] 83 5a [2] 8f 50 [2] 98 5b [2] 83 15 [2] be }

  condition:
    any of them
}