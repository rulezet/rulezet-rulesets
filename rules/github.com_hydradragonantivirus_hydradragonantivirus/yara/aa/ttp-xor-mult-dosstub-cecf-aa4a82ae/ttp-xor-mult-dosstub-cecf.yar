rule TTP_XOR_MULT_DOSStub_cecf {
  strings:
    $key_cecf = { 9a a7 [2] ee bf [2] a9 bd [2] ee ac [2] a0 a0 [2] ac aa [2] bb a1 [2] a0 ef [2] 9d }

  condition:
    any of them
}