rule TTP_XOR_MULT_DOSStub_cdfb {
  strings:
    $key_cdfb = { 99 93 [2] ed 8b [2] aa 89 [2] ed 98 [2] a3 94 [2] af 9e [2] b8 95 [2] a3 db [2] 9e }

  condition:
    any of them
}