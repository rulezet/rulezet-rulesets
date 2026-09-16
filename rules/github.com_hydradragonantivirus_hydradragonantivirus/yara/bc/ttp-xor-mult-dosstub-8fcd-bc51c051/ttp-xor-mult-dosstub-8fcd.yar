rule TTP_XOR_MULT_DOSStub_8fcd {
  strings:
    $key_8fcd = { db a5 [2] af bd [2] e8 bf [2] af ae [2] e1 a2 [2] ed a8 [2] fa a3 [2] e1 ed [2] dc }

  condition:
    any of them
}