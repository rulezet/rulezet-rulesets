rule TTP_XOR_QUAD_CurrentVersionRun_17de {
  strings:
    $key_17de = { 44 b1 [2] 60 bf [2] 4b 93 [2] 65 b1 [2] 71 aa [2] 7e b0 [2] 60 ad [2] 62 ac [2] 79 aa [2] 65 ad [2] 79 82 }

  condition:
    any of them
}