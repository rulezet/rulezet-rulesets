rule TTP_XOR_QUAD_CurrentVersionRun_b2cd {
  strings:
    $key_b2cd = { e1 a2 [2] c5 ac [2] ee 80 [2] c0 a2 [2] d4 b9 [2] db a3 [2] c5 be [2] c7 bf [2] dc b9 [2] c0 be [2] dc 91 }

  condition:
    any of them
}