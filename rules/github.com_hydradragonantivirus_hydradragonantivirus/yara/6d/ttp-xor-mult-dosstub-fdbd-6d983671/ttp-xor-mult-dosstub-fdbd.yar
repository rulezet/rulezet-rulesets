rule TTP_XOR_MULT_DOSStub_fdbd {
  strings:
    $key_fdbd = { a9 d5 [2] dd cd [2] 9a cf [2] dd de [2] 93 d2 [2] 9f d8 [2] 88 d3 [2] 93 9d [2] ae }

  condition:
    any of them
}