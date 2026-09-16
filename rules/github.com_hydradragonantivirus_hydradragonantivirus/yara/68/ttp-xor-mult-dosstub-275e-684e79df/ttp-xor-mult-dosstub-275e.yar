rule TTP_XOR_MULT_DOSStub_275e {
  strings:
    $key_275e = { 73 36 [2] 07 2e [2] 40 2c [2] 07 3d [2] 49 31 [2] 45 3b [2] 52 30 [2] 49 7e [2] 74 }

  condition:
    any of them
}