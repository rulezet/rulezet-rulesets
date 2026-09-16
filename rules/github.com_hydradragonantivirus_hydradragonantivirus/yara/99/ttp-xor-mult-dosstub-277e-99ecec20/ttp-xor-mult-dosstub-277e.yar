rule TTP_XOR_MULT_DOSStub_277e {
  strings:
    $key_277e = { 73 16 [2] 07 0e [2] 40 0c [2] 07 1d [2] 49 11 [2] 45 1b [2] 52 10 [2] 49 5e [2] 74 }

  condition:
    any of them
}