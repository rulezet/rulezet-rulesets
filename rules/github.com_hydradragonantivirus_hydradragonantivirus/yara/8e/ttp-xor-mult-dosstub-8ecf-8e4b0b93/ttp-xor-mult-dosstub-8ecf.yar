rule TTP_XOR_MULT_DOSStub_8ecf {
  strings:
    $key_8ecf = { da a7 [2] ae bf [2] e9 bd [2] ae ac [2] e0 a0 [2] ec aa [2] fb a1 [2] e0 ef [2] dd }

  condition:
    any of them
}