rule TTP_XOR_QUAD_CurrentVersionRun_dbde {
  strings:
    $key_dbde = { 88 b1 [2] ac bf [2] 87 93 [2] a9 b1 [2] bd aa [2] b2 b0 [2] ac ad [2] ae ac [2] b5 aa [2] a9 ad [2] b5 82 }

  condition:
    any of them
}