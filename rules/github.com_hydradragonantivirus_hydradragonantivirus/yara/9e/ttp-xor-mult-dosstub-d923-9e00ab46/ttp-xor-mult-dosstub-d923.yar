rule TTP_XOR_MULT_DOSStub_d923 {
  strings:
    $key_d923 = { 8d 4b [2] f9 53 [2] be 51 [2] f9 40 [2] b7 4c [2] bb 46 [2] ac 4d [2] b7 03 [2] 8a }

  condition:
    any of them
}