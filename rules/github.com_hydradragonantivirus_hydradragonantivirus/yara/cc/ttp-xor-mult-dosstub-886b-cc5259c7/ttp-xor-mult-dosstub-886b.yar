rule TTP_XOR_MULT_DOSStub_886b {
  strings:
    $key_886b = { dc 03 [2] a8 1b [2] ef 19 [2] a8 08 [2] e6 04 [2] ea 0e [2] fd 05 [2] e6 4b [2] db }

  condition:
    any of them
}