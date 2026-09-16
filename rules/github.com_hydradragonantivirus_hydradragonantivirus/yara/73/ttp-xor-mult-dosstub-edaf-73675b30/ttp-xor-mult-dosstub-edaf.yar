rule TTP_XOR_MULT_DOSStub_edaf {
  strings:
    $key_edaf = { b9 c7 [2] cd df [2] 8a dd [2] cd cc [2] 83 c0 [2] 8f ca [2] 98 c1 [2] 83 8f [2] be }

  condition:
    any of them
}