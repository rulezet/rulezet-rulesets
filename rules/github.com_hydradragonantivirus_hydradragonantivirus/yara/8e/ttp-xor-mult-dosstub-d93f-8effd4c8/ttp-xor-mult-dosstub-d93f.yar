rule TTP_XOR_MULT_DOSStub_d93f {
  strings:
    $key_d93f = { 8d 57 [2] f9 4f [2] be 4d [2] f9 5c [2] b7 50 [2] bb 5a [2] ac 51 [2] b7 1f [2] 8a }

  condition:
    any of them
}