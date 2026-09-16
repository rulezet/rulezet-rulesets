rule TTP_XOR_MULT_DOSStub_ed55 {
  strings:
    $key_ed55 = { b9 3d [2] cd 25 [2] 8a 27 [2] cd 36 [2] 83 3a [2] 8f 30 [2] 98 3b [2] 83 75 [2] be }

  condition:
    any of them
}