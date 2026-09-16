rule TTP_XOR_MULT_DOSStub_249f {
  strings:
    $key_249f = { 70 f7 [2] 04 ef [2] 43 ed [2] 04 fc [2] 4a f0 [2] 46 fa [2] 51 f1 [2] 4a bf [2] 77 }

  condition:
    any of them
}