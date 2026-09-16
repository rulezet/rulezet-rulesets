rule TTP_XOR_MULT_DOSStub_269f {
  strings:
    $key_269f = { 72 f7 [2] 06 ef [2] 41 ed [2] 06 fc [2] 48 f0 [2] 44 fa [2] 53 f1 [2] 48 bf [2] 75 }

  condition:
    any of them
}