rule TTP_XOR_MULT_DOSStub_a9ae {
  strings:
    $key_a9ae = { fd c6 [2] 89 de [2] ce dc [2] 89 cd [2] c7 c1 [2] cb cb [2] dc c0 [2] c7 8e [2] fa }

  condition:
    any of them
}