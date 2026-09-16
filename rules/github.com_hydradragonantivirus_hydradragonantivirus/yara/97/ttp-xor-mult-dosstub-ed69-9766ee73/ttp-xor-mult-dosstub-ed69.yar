rule TTP_XOR_MULT_DOSStub_ed69 {
  strings:
    $key_ed69 = { b9 01 [2] cd 19 [2] 8a 1b [2] cd 0a [2] 83 06 [2] 8f 0c [2] 98 07 [2] 83 49 [2] be }

  condition:
    any of them
}