rule TTP_XOR_MULT_DOSStub_ee9f {
  strings:
    $key_ee9f = { ba f7 [2] ce ef [2] 89 ed [2] ce fc [2] 80 f0 [2] 8c fa [2] 9b f1 [2] 80 bf [2] bd }

  condition:
    any of them
}