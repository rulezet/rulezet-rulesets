rule TTP_XOR_MULT_DOSStub_5aea {
  strings:
    $key_5aea = { 0e 82 [2] 7a 9a [2] 3d 98 [2] 7a 89 [2] 34 85 [2] 38 8f [2] 2f 84 [2] 34 ca [2] 09 }

  condition:
    any of them
}