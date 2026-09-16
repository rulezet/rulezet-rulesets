rule TTP_XOR_MULT_DOSStub_0e9f {
  strings:
    $key_0e9f = { 5a f7 [2] 2e ef [2] 69 ed [2] 2e fc [2] 60 f0 [2] 6c fa [2] 7b f1 [2] 60 bf [2] 5d }

  condition:
    any of them
}