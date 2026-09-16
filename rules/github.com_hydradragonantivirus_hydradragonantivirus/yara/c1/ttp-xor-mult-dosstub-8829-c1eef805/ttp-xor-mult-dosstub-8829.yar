rule TTP_XOR_MULT_DOSStub_8829 {
  strings:
    $key_8829 = { dc 41 [2] a8 59 [2] ef 5b [2] a8 4a [2] e6 46 [2] ea 4c [2] fd 47 [2] e6 09 [2] db }

  condition:
    any of them
}