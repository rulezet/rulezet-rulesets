rule TTP_XOR_MULT_DOSStub_f99f {
  strings:
    $key_f99f = { ad f7 [2] d9 ef [2] 9e ed [2] d9 fc [2] 97 f0 [2] 9b fa [2] 8c f1 [2] 97 bf [2] aa }

  condition:
    any of them
}