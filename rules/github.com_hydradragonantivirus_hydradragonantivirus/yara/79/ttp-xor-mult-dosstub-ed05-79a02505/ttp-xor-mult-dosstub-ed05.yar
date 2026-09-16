rule TTP_XOR_MULT_DOSStub_ed05 {
  strings:
    $key_ed05 = { b9 6d [2] cd 75 [2] 8a 77 [2] cd 66 [2] 83 6a [2] 8f 60 [2] 98 6b [2] 83 25 [2] be }

  condition:
    any of them
}