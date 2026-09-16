rule TTP_XOR_QUAD_CurrentVersionRun_7872 {
  strings:
    $key_7872 = { 2b 1d [2] 0f 13 [2] 24 3f [2] 0a 1d [2] 1e 06 [2] 11 1c [2] 0f 01 [2] 0d 00 [2] 16 06 [2] 0a 01 [2] 16 2e }

  condition:
    any of them
}