rule TTP_XOR_MULT_DOSStub_680e {
  strings:
    $key_680e = { 3c 66 [2] 48 7e [2] 0f 7c [2] 48 6d [2] 06 61 [2] 0a 6b [2] 1d 60 [2] 06 2e [2] 3b }

  condition:
    any of them
}