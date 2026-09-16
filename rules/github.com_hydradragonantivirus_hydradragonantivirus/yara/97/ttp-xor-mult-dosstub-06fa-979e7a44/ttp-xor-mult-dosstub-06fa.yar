rule TTP_XOR_MULT_DOSStub_06fa {
  strings:
    $key_06fa = { 52 92 [2] 26 8a [2] 61 88 [2] 26 99 [2] 68 95 [2] 64 9f [2] 73 94 [2] 68 da [2] 55 }

  condition:
    any of them
}