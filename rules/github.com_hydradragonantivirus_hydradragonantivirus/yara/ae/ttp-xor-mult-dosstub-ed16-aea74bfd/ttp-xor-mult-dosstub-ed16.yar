rule TTP_XOR_MULT_DOSStub_ed16 {
  strings:
    $key_ed16 = { b9 7e [2] cd 66 [2] 8a 64 [2] cd 75 [2] 83 79 [2] 8f 73 [2] 98 78 [2] 83 36 [2] be }

  condition:
    any of them
}