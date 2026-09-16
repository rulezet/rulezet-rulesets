rule TTP_XOR_MULT_DOSStub_151e {
  strings:
    $key_151e = { 41 76 [2] 35 6e [2] 72 6c [2] 35 7d [2] 7b 71 [2] 77 7b [2] 60 70 [2] 7b 3e [2] 46 }

  condition:
    any of them
}