rule TTP_XOR_QUAD_CurrentVersionRun_2ede {
  strings:
    $key_2ede = { 7d b1 [2] 59 bf [2] 72 93 [2] 5c b1 [2] 48 aa [2] 47 b0 [2] 59 ad [2] 5b ac [2] 40 aa [2] 5c ad [2] 40 82 }

  condition:
    any of them
}