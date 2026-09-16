rule TTP_XOR_MULT_DOSStub_edf4 {
  strings:
    $key_edf4 = { b9 9c [2] cd 84 [2] 8a 86 [2] cd 97 [2] 83 9b [2] 8f 91 [2] 98 9a [2] 83 d4 [2] be }

  condition:
    any of them
}