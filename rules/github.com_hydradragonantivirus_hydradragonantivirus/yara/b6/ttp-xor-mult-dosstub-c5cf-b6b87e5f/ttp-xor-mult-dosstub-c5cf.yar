rule TTP_XOR_MULT_DOSStub_c5cf {
  strings:
    $key_c5cf = { 91 a7 [2] e5 bf [2] a2 bd [2] e5 ac [2] ab a0 [2] a7 aa [2] b0 a1 [2] ab ef [2] 96 }

  condition:
    any of them
}