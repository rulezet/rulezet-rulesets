rule TTP_XOR_MULT_DOSStub_d62f {
  strings:
    $key_d62f = { 82 47 [2] f6 5f [2] b1 5d [2] f6 4c [2] b8 40 [2] b4 4a [2] a3 41 [2] b8 0f [2] 85 }

  condition:
    any of them
}