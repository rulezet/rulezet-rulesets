rule TTP_XOR_MULT_DOSStub_8f0b {
  strings:
    $key_8f0b = { db 63 [2] af 7b [2] e8 79 [2] af 68 [2] e1 64 [2] ed 6e [2] fa 65 [2] e1 2b [2] dc }

  condition:
    any of them
}