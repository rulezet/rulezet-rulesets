rule TTP_XOR_MULT_DOSStub_a8ad {
  strings:
    $key_a8ad = { fc c5 [2] 88 dd [2] cf df [2] 88 ce [2] c6 c2 [2] ca c8 [2] dd c3 [2] c6 8d [2] fb }

  condition:
    any of them
}