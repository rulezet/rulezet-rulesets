rule TTP_XOR_MULT_DOSStub_f89f {
  strings:
    $key_f89f = { ac f7 [2] d8 ef [2] 9f ed [2] d8 fc [2] 96 f0 [2] 9a fa [2] 8d f1 [2] 96 bf [2] ab }

  condition:
    any of them
}