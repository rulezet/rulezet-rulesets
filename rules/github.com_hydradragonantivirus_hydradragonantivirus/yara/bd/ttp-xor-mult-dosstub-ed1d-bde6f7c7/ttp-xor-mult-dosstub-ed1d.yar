rule TTP_XOR_MULT_DOSStub_ed1d {
  strings:
    $key_ed1d = { b9 75 [2] cd 6d [2] 8a 6f [2] cd 7e [2] 83 72 [2] 8f 78 [2] 98 73 [2] 83 3d [2] be }

  condition:
    any of them
}