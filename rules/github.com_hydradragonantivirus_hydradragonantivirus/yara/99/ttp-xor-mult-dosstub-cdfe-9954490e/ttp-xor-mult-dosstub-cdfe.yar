rule TTP_XOR_MULT_DOSStub_cdfe {
  strings:
    $key_cdfe = { 99 96 [2] ed 8e [2] aa 8c [2] ed 9d [2] a3 91 [2] af 9b [2] b8 90 [2] a3 de [2] 9e }

  condition:
    any of them
}