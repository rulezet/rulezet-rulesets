rule TTP_XOR_MULT_DOSStub_b19f {
  strings:
    $key_b19f = { e5 f7 [2] 91 ef [2] d6 ed [2] 91 fc [2] df f0 [2] d3 fa [2] c4 f1 [2] df bf [2] e2 }

  condition:
    any of them
}