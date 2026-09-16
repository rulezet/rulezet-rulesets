rule TTP_XOR_MULT_DOSStub_ed1c {
  strings:
    $key_ed1c = { b9 74 [2] cd 6c [2] 8a 6e [2] cd 7f [2] 83 73 [2] 8f 79 [2] 98 72 [2] 83 3c [2] be }

  condition:
    any of them
}