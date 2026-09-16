rule TTP_XOR_MULT_DOSStub_d02f {
  strings:
    $key_d02f = { 84 47 [2] f0 5f [2] b7 5d [2] f0 4c [2] be 40 [2] b2 4a [2] a5 41 [2] be 0f [2] 83 }

  condition:
    any of them
}