rule TTP_XOR_MULT_DOSStub_fdbf {
  strings:
    $key_fdbf = { a9 d7 [2] dd cf [2] 9a cd [2] dd dc [2] 93 d0 [2] 9f da [2] 88 d1 [2] 93 9f [2] ae }

  condition:
    any of them
}