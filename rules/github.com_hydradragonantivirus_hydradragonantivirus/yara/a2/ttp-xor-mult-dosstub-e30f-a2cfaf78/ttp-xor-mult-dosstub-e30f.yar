rule TTP_XOR_MULT_DOSStub_e30f {
  strings:
    $key_e30f = { b7 67 [2] c3 7f [2] 84 7d [2] c3 6c [2] 8d 60 [2] 81 6a [2] 96 61 [2] 8d 2f [2] b0 }

  condition:
    any of them
}