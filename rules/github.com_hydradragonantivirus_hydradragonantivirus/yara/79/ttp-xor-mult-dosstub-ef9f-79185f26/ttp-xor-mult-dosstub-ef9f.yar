rule TTP_XOR_MULT_DOSStub_ef9f {
  strings:
    $key_ef9f = { bb f7 [2] cf ef [2] 88 ed [2] cf fc [2] 81 f0 [2] 8d fa [2] 9a f1 [2] 81 bf [2] bc }

  condition:
    any of them
}