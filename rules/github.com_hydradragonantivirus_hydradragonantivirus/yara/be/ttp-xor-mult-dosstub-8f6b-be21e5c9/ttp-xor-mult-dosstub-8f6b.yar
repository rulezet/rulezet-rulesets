rule TTP_XOR_MULT_DOSStub_8f6b {
  strings:
    $key_8f6b = { db 03 [2] af 1b [2] e8 19 [2] af 08 [2] e1 04 [2] ed 0e [2] fa 05 [2] e1 4b [2] dc }

  condition:
    any of them
}