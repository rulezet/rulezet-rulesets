rule TTP_XOR_MULT_DOSStub_edf3 {
  strings:
    $key_edf3 = { b9 9b [2] cd 83 [2] 8a 81 [2] cd 90 [2] 83 9c [2] 8f 96 [2] 98 9d [2] 83 d3 [2] be }

  condition:
    any of them
}