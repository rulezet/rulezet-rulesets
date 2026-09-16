rule TTP_XOR_MULT_DOSStub_ed24 {
  strings:
    $key_ed24 = { b9 4c [2] cd 54 [2] 8a 56 [2] cd 47 [2] 83 4b [2] 8f 41 [2] 98 4a [2] 83 04 [2] be }

  condition:
    any of them
}