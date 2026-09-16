rule TTP_XOR_MULT_DOSStub_1e9f {
  strings:
    $key_1e9f = { 4a f7 [2] 3e ef [2] 79 ed [2] 3e fc [2] 70 f0 [2] 7c fa [2] 6b f1 [2] 70 bf [2] 4d }

  condition:
    any of them
}