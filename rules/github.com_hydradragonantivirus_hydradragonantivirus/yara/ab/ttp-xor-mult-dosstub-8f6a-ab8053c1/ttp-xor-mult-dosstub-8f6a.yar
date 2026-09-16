rule TTP_XOR_MULT_DOSStub_8f6a {
  strings:
    $key_8f6a = { db 02 [2] af 1a [2] e8 18 [2] af 09 [2] e1 05 [2] ed 0f [2] fa 04 [2] e1 4a [2] dc }

  condition:
    any of them
}