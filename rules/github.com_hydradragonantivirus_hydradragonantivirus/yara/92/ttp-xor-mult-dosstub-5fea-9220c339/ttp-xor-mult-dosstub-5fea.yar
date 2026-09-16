rule TTP_XOR_MULT_DOSStub_5fea {
  strings:
    $key_5fea = { 0b 82 [2] 7f 9a [2] 38 98 [2] 7f 89 [2] 31 85 [2] 3d 8f [2] 2a 84 [2] 31 ca [2] 0c }

  condition:
    any of them
}