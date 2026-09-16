rule TTP_XOR_MULT_DOSStub_a91b {
  strings:
    $key_a91b = { fd 73 [2] 89 6b [2] ce 69 [2] 89 78 [2] c7 74 [2] cb 7e [2] dc 75 [2] c7 3b [2] fa }

  condition:
    any of them
}