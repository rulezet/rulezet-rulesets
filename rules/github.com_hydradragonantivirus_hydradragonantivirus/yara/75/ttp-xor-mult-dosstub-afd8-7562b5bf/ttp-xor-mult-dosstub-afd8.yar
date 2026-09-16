rule TTP_XOR_MULT_DOSStub_afd8 {
  strings:
    $key_afd8 = { fb b0 [2] 8f a8 [2] c8 aa [2] 8f bb [2] c1 b7 [2] cd bd [2] da b6 [2] c1 f8 [2] fc }

  condition:
    any of them
}