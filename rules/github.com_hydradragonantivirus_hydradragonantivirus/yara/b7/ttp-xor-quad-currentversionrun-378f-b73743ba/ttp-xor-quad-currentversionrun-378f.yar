rule TTP_XOR_QUAD_CurrentVersionRun_378f {
  strings:
    $key_378f = { 64 e0 [2] 40 ee [2] 6b c2 [2] 45 e0 [2] 51 fb [2] 5e e1 [2] 40 fc [2] 42 fd [2] 59 fb [2] 45 fc [2] 59 d3 }

  condition:
    any of them
}