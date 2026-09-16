rule TTP_XOR_MULT_DOSStub_2fbc {
  strings:
    $key_2fbc = { 7b d4 [2] 0f cc [2] 48 ce [2] 0f df [2] 41 d3 [2] 4d d9 [2] 5a d2 [2] 41 9c [2] 7c }

  condition:
    any of them
}