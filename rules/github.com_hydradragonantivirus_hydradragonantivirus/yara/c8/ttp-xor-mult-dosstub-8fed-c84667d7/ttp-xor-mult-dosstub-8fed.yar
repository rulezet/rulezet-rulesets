rule TTP_XOR_MULT_DOSStub_8fed {
  strings:
    $key_8fed = { db 85 [2] af 9d [2] e8 9f [2] af 8e [2] e1 82 [2] ed 88 [2] fa 83 [2] e1 cd [2] dc }

  condition:
    any of them
}