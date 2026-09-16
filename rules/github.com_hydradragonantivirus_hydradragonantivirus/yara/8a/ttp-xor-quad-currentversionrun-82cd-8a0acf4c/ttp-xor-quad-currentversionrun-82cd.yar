rule TTP_XOR_QUAD_CurrentVersionRun_82cd {
  strings:
    $key_82cd = { d1 a2 [2] f5 ac [2] de 80 [2] f0 a2 [2] e4 b9 [2] eb a3 [2] f5 be [2] f7 bf [2] ec b9 [2] f0 be [2] ec 91 }

  condition:
    any of them
}