rule TTP_XOR_MULT_DOSStub_105e {
  strings:
    $key_105e = { 44 36 [2] 30 2e [2] 77 2c [2] 30 3d [2] 7e 31 [2] 72 3b [2] 65 30 [2] 7e 7e [2] 43 }

  condition:
    any of them
}