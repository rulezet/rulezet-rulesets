rule TTP_XOR_MULT_DOSStub_8ffe {
  strings:
    $key_8ffe = { db 96 [2] af 8e [2] e8 8c [2] af 9d [2] e1 91 [2] ed 9b [2] fa 90 [2] e1 de [2] dc }

  condition:
    any of them
}