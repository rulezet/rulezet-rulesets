rule TTP_XOR_MULT_DOSStub_d939 {
  strings:
    $key_d939 = { 8d 51 [2] f9 49 [2] be 4b [2] f9 5a [2] b7 56 [2] bb 5c [2] ac 57 [2] b7 19 [2] 8a }

  condition:
    any of them
}