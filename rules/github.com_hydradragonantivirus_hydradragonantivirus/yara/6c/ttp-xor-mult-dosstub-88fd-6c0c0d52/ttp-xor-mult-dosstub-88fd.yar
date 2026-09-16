rule TTP_XOR_MULT_DOSStub_88fd {
  strings:
    $key_88fd = { dc 95 [2] a8 8d [2] ef 8f [2] a8 9e [2] e6 92 [2] ea 98 [2] fd 93 [2] e6 dd [2] db }

  condition:
    any of them
}