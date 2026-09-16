rule TTP_XOR_MULT_DOSStub_88cc {
  strings:
    $key_88cc = { dc a4 [2] a8 bc [2] ef be [2] a8 af [2] e6 a3 [2] ea a9 [2] fd a2 [2] e6 ec [2] db }

  condition:
    any of them
}