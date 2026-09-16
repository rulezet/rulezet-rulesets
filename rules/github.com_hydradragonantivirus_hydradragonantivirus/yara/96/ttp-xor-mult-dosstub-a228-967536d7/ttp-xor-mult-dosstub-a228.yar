rule TTP_XOR_MULT_DOSStub_a228 {
  strings:
    $key_a228 = { f6 40 [2] 82 58 [2] c5 5a [2] 82 4b [2] cc 47 [2] c0 4d [2] d7 46 [2] cc 08 [2] f1 }

  condition:
    any of them
}