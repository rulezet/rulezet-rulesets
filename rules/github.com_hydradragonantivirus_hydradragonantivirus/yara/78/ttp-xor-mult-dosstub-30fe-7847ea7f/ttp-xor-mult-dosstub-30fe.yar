rule TTP_XOR_MULT_DOSStub_30fe {
  strings:
    $key_30fe = { 64 96 [2] 10 8e [2] 57 8c [2] 10 9d [2] 5e 91 [2] 52 9b [2] 45 90 [2] 5e de [2] 63 }

  condition:
    any of them
}