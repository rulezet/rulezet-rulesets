rule TTP_XOR_MULT_DOSStub_ed53 {
  strings:
    $key_ed53 = { b9 3b [2] cd 23 [2] 8a 21 [2] cd 30 [2] 83 3c [2] 8f 36 [2] 98 3d [2] 83 73 [2] be }

  condition:
    any of them
}