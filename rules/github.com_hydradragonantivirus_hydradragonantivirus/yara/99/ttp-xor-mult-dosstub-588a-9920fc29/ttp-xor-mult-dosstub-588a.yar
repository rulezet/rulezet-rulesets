rule TTP_XOR_MULT_DOSStub_588a {
  strings:
    $key_588a = { 0c e2 [2] 78 fa [2] 3f f8 [2] 78 e9 [2] 36 e5 [2] 3a ef [2] 2d e4 [2] 36 aa [2] 0b }

  condition:
    any of them
}