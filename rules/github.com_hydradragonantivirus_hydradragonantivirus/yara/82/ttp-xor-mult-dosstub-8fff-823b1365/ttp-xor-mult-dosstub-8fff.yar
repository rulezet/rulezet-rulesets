rule TTP_XOR_MULT_DOSStub_8fff {
  strings:
    $key_8fff = { db 97 [2] af 8f [2] e8 8d [2] af 9c [2] e1 90 [2] ed 9a [2] fa 91 [2] e1 df [2] dc }

  condition:
    any of them
}