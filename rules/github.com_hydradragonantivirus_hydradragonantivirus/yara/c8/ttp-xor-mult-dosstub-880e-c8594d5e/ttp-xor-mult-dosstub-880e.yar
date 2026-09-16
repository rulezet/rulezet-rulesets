rule TTP_XOR_MULT_DOSStub_880e {
  strings:
    $key_880e = { dc 66 [2] a8 7e [2] ef 7c [2] a8 6d [2] e6 61 [2] ea 6b [2] fd 60 [2] e6 2e [2] db }

  condition:
    any of them
}