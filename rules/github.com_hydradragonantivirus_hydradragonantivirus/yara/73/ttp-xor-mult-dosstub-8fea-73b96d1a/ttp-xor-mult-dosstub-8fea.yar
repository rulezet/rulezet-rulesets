rule TTP_XOR_MULT_DOSStub_8fea {
  strings:
    $key_8fea = { db 82 [2] af 9a [2] e8 98 [2] af 89 [2] e1 85 [2] ed 8f [2] fa 84 [2] e1 ca [2] dc }

  condition:
    any of them
}