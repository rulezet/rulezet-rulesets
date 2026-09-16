rule TTP_XOR_MULT_DOSStub_daee {
  strings:
    $key_daee = { 8e 86 [2] fa 9e [2] bd 9c [2] fa 8d [2] b4 81 [2] b8 8b [2] af 80 [2] b4 ce [2] 89 }

  condition:
    any of them
}