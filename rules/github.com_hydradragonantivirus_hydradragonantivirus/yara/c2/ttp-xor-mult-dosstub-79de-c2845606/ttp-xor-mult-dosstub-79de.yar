rule TTP_XOR_MULT_DOSStub_79de {
  strings:
    $key_79de = { 2d b6 [2] 59 ae [2] 1e ac [2] 59 bd [2] 17 b1 [2] 1b bb [2] 0c b0 [2] 17 fe [2] 2a }

  condition:
    any of them
}