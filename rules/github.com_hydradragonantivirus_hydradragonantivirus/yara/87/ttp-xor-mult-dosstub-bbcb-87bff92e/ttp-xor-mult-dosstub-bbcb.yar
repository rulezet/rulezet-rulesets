rule TTP_XOR_MULT_DOSStub_bbcb {
  strings:
    $key_bbcb = { ef a3 [2] 9b bb [2] dc b9 [2] 9b a8 [2] d5 a4 [2] d9 ae [2] ce a5 [2] d5 eb [2] e8 }

  condition:
    any of them
}