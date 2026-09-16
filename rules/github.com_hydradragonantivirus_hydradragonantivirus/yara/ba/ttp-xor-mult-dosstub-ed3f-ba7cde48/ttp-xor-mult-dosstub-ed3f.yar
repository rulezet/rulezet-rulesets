rule TTP_XOR_MULT_DOSStub_ed3f {
  strings:
    $key_ed3f = { b9 57 [2] cd 4f [2] 8a 4d [2] cd 5c [2] 83 50 [2] 8f 5a [2] 98 51 [2] 83 1f [2] be }

  condition:
    any of them
}