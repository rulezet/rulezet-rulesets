rule TTP_XOR_MULT_DOSStub_a89f {
  strings:
    $key_a89f = { fc f7 [2] 88 ef [2] cf ed [2] 88 fc [2] c6 f0 [2] ca fa [2] dd f1 [2] c6 bf [2] fb }

  condition:
    any of them
}