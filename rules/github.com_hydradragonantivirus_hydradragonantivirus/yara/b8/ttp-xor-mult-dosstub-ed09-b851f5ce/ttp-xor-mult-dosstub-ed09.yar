rule TTP_XOR_MULT_DOSStub_ed09 {
  strings:
    $key_ed09 = { b9 61 [2] cd 79 [2] 8a 7b [2] cd 6a [2] 83 66 [2] 8f 6c [2] 98 67 [2] 83 29 [2] be }

  condition:
    any of them
}