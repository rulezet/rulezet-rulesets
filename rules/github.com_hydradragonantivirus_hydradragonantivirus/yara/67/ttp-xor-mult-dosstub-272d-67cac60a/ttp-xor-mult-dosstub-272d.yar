rule TTP_XOR_MULT_DOSStub_272d {
  strings:
    $key_272d = { 73 45 [2] 07 5d [2] 40 5f [2] 07 4e [2] 49 42 [2] 45 48 [2] 52 43 [2] 49 0d [2] 74 }

  condition:
    any of them
}