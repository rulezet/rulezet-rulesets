rule TTP_XOR_MULT_DOSStub_4aea {
  strings:
    $key_4aea = { 1e 82 [2] 6a 9a [2] 2d 98 [2] 6a 89 [2] 24 85 [2] 28 8f [2] 3f 84 [2] 24 ca [2] 19 }

  condition:
    any of them
}