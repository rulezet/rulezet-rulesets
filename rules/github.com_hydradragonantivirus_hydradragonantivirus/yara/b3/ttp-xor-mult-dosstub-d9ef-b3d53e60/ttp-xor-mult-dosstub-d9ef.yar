rule TTP_XOR_MULT_DOSStub_d9ef {
  strings:
    $key_d9ef = { 8d 87 [2] f9 9f [2] be 9d [2] f9 8c [2] b7 80 [2] bb 8a [2] ac 81 [2] b7 cf [2] 8a }

  condition:
    any of them
}