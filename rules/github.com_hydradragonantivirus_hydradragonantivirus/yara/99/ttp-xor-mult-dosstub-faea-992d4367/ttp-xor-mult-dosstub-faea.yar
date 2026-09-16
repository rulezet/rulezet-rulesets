rule TTP_XOR_MULT_DOSStub_faea {
  strings:
    $key_faea = { ae 82 [2] da 9a [2] 9d 98 [2] da 89 [2] 94 85 [2] 98 8f [2] 8f 84 [2] 94 ca [2] a9 }

  condition:
    any of them
}