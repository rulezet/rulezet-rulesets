rule TTP_XOR_MULT_DOSStub_aefb {
  strings:
    $key_aefb = { fa 93 [2] 8e 8b [2] c9 89 [2] 8e 98 [2] c0 94 [2] cc 9e [2] db 95 [2] c0 db [2] fd }

  condition:
    any of them
}