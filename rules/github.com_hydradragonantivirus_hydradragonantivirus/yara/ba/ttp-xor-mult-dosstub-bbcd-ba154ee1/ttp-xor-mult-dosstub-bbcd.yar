rule TTP_XOR_MULT_DOSStub_bbcd {
  strings:
    $key_bbcd = { ef a5 [2] 9b bd [2] dc bf [2] 9b ae [2] d5 a2 [2] d9 a8 [2] ce a3 [2] d5 ed [2] e8 }

  condition:
    any of them
}