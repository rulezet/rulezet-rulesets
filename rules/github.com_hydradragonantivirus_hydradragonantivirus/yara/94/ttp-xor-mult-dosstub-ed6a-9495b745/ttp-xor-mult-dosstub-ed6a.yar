rule TTP_XOR_MULT_DOSStub_ed6a {
  strings:
    $key_ed6a = { b9 02 [2] cd 1a [2] 8a 18 [2] cd 09 [2] 83 05 [2] 8f 0f [2] 98 04 [2] 83 4a [2] be }

  condition:
    any of them
}