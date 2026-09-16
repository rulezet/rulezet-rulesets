rule TTP_XOR_MULT_DOSStub_caea {
  strings:
    $key_caea = { 9e 82 [2] ea 9a [2] ad 98 [2] ea 89 [2] a4 85 [2] a8 8f [2] bf 84 [2] a4 ca [2] 99 }

  condition:
    any of them
}