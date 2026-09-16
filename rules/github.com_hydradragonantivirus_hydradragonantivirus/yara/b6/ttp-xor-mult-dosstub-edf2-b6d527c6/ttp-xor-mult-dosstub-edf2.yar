rule TTP_XOR_MULT_DOSStub_edf2 {
  strings:
    $key_edf2 = { b9 9a [2] cd 82 [2] 8a 80 [2] cd 91 [2] 83 9d [2] 8f 97 [2] 98 9c [2] 83 d2 [2] be }

  condition:
    any of them
}