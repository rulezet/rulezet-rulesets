rule TTP_XOR_MULT_DOSStub_88dc {
  strings:
    $key_88dc = { dc b4 [2] a8 ac [2] ef ae [2] a8 bf [2] e6 b3 [2] ea b9 [2] fd b2 [2] e6 fc [2] db }

  condition:
    any of them
}