rule TTP_XOR_QUAD_CurrentVersionRun_7ede {
  strings:
    $key_7ede = { 2d b1 [2] 09 bf [2] 22 93 [2] 0c b1 [2] 18 aa [2] 17 b0 [2] 09 ad [2] 0b ac [2] 10 aa [2] 0c ad [2] 10 82 }

  condition:
    any of them
}