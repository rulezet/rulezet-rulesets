rule TTP_XOR_MULT_DOSStub_ed59 {
  strings:
    $key_ed59 = { b9 31 [2] cd 29 [2] 8a 2b [2] cd 3a [2] 83 36 [2] 8f 3c [2] 98 37 [2] 83 79 [2] be }

  condition:
    any of them
}