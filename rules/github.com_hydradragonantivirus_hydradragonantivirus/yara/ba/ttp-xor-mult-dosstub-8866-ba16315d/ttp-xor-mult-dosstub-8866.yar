rule TTP_XOR_MULT_DOSStub_8866 {
  strings:
    $key_8866 = { dc 0e [2] a8 16 [2] ef 14 [2] a8 05 [2] e6 09 [2] ea 03 [2] fd 08 [2] e6 46 [2] db }

  condition:
    any of them
}