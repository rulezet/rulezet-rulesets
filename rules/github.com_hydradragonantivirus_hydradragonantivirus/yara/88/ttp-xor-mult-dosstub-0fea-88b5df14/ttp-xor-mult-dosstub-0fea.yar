rule TTP_XOR_MULT_DOSStub_0fea {
  strings:
    $key_0fea = { 5b 82 [2] 2f 9a [2] 68 98 [2] 2f 89 [2] 61 85 [2] 6d 8f [2] 7a 84 [2] 61 ca [2] 5c }

  condition:
    any of them
}