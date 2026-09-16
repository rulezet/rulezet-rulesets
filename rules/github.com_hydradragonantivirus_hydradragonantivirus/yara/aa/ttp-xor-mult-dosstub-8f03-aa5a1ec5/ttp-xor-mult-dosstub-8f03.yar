rule TTP_XOR_MULT_DOSStub_8f03 {
  strings:
    $key_8f03 = { db 6b [2] af 73 [2] e8 71 [2] af 60 [2] e1 6c [2] ed 66 [2] fa 6d [2] e1 23 [2] dc }

  condition:
    any of them
}