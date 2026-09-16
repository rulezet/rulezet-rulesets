rule TTP_XOR_MULT_DOSStub_edff {
  strings:
    $key_edff = { b9 97 [2] cd 8f [2] 8a 8d [2] cd 9c [2] 83 90 [2] 8f 9a [2] 98 91 [2] 83 df [2] be }

  condition:
    any of them
}