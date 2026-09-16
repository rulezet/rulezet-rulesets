rule TTP_XOR_MULT_DOSStub_9abf {
  strings:
    $key_9abf = { ce d7 [2] ba cf [2] fd cd [2] ba dc [2] f4 d0 [2] f8 da [2] ef d1 [2] f4 9f [2] c9 }

  condition:
    any of them
}