rule TTP_XOR_MULT_DOSStub_880f {
  strings:
    $key_880f = { dc 67 [2] a8 7f [2] ef 7d [2] a8 6c [2] e6 60 [2] ea 6a [2] fd 61 [2] e6 2f [2] db }

  condition:
    any of them
}