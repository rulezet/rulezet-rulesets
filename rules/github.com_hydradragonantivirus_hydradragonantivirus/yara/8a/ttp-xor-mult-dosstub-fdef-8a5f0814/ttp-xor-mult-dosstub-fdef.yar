rule TTP_XOR_MULT_DOSStub_fdef {
  strings:
    $key_fdef = { a9 87 [2] dd 9f [2] 9a 9d [2] dd 8c [2] 93 80 [2] 9f 8a [2] 88 81 [2] 93 cf [2] ae }

  condition:
    any of them
}