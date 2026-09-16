rule TTP_XOR_MULT_DOSStub_bbea {
  strings:
    $key_bbea = { ef 82 [2] 9b 9a [2] dc 98 [2] 9b 89 [2] d5 85 [2] d9 8f [2] ce 84 [2] d5 ca [2] e8 }

  condition:
    any of them
}