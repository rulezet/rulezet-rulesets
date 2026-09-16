rule TTP_XOR_QUAD_CurrentVersionRun_96cd {
  strings:
    $key_96cd = { c5 a2 [2] e1 ac [2] ca 80 [2] e4 a2 [2] f0 b9 [2] ff a3 [2] e1 be [2] e3 bf [2] f8 b9 [2] e4 be [2] f8 91 }

  condition:
    any of them
}