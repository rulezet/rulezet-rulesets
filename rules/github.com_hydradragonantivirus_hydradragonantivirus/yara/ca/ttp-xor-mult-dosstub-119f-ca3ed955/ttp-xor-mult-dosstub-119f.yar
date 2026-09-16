rule TTP_XOR_MULT_DOSStub_119f {
  strings:
    $key_119f = { 45 f7 [2] 31 ef [2] 76 ed [2] 31 fc [2] 7f f0 [2] 73 fa [2] 64 f1 [2] 7f bf [2] 42 }

  condition:
    any of them
}