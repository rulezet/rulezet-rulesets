rule TTP_XOR_QUAD_CurrentVersionRun_6ede {
  strings:
    $key_6ede = { 3d b1 [2] 19 bf [2] 32 93 [2] 1c b1 [2] 08 aa [2] 07 b0 [2] 19 ad [2] 1b ac [2] 00 aa [2] 1c ad [2] 00 82 }

  condition:
    any of them
}