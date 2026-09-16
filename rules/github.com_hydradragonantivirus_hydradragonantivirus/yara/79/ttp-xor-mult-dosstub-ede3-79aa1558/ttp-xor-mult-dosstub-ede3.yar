rule TTP_XOR_MULT_DOSStub_ede3 {
  strings:
    $key_ede3 = { b9 8b [2] cd 93 [2] 8a 91 [2] cd 80 [2] 83 8c [2] 8f 86 [2] 98 8d [2] 83 c3 [2] be }

  condition:
    any of them
}