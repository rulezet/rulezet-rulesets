rule TTP_XOR_MULT_DOSStub_1faf {
  strings:
    $key_1faf = { 4b c7 [2] 3f df [2] 78 dd [2] 3f cc [2] 71 c0 [2] 7d ca [2] 6a c1 [2] 71 8f [2] 4c }

  condition:
    any of them
}