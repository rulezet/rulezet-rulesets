rule TTP_XOR_MULT_DOSStub_ed1f {
  strings:
    $key_ed1f = { b9 77 [2] cd 6f [2] 8a 6d [2] cd 7c [2] 83 70 [2] 8f 7a [2] 98 71 [2] 83 3f [2] be }

  condition:
    any of them
}