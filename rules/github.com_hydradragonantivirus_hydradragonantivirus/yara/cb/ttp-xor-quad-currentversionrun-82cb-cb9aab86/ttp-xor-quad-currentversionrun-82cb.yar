rule TTP_XOR_QUAD_CurrentVersionRun_82cb {
  strings:
    $key_82cb = { d1 a4 [2] f5 aa [2] de 86 [2] f0 a4 [2] e4 bf [2] eb a5 [2] f5 b8 [2] f7 b9 [2] ec bf [2] f0 b8 [2] ec 97 }

  condition:
    any of them
}