rule TTP_XOR_MULT_DOSStub_ed25 {
  strings:
    $key_ed25 = { b9 4d [2] cd 55 [2] 8a 57 [2] cd 46 [2] 83 4a [2] 8f 40 [2] 98 4b [2] 83 05 [2] be }

  condition:
    any of them
}