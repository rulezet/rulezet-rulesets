rule TTP_XOR_MULT_DOSStub_a91f {
  strings:
    $key_a91f = { fd 77 [2] 89 6f [2] ce 6d [2] 89 7c [2] c7 70 [2] cb 7a [2] dc 71 [2] c7 3f [2] fa }

  condition:
    any of them
}