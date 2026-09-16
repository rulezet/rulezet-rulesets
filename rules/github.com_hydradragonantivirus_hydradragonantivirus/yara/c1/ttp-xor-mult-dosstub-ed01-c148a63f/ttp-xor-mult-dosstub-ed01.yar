rule TTP_XOR_MULT_DOSStub_ed01 {
  strings:
    $key_ed01 = { b9 69 [2] cd 71 [2] 8a 73 [2] cd 62 [2] 83 6e [2] 8f 64 [2] 98 6f [2] 83 21 [2] be }

  condition:
    any of them
}