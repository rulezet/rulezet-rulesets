rule TTP_XOR_QUAD_CurrentVersionRun_dede {
  strings:
    $key_dede = { 8d b1 [2] a9 bf [2] 82 93 [2] ac b1 [2] b8 aa [2] b7 b0 [2] a9 ad [2] ab ac [2] b0 aa [2] ac ad [2] b0 82 }

  condition:
    any of them
}