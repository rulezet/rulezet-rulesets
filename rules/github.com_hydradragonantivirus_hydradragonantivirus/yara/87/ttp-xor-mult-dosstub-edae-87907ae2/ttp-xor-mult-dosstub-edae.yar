rule TTP_XOR_MULT_DOSStub_edae {
  strings:
    $key_edae = { b9 c6 [2] cd de [2] 8a dc [2] cd cd [2] 83 c1 [2] 8f cb [2] 98 c0 [2] 83 8e [2] be }

  condition:
    any of them
}