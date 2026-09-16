rule TTP_XOR_MULT_DOSStub_d90f {
  strings:
    $key_d90f = { 8d 67 [2] f9 7f [2] be 7d [2] f9 6c [2] b7 60 [2] bb 6a [2] ac 61 [2] b7 2f [2] 8a }

  condition:
    any of them
}