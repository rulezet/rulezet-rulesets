rule TTP_XOR_QUAD_CurrentVersionRun_b2cb {
  strings:
    $key_b2cb = { e1 a4 [2] c5 aa [2] ee 86 [2] c0 a4 [2] d4 bf [2] db a5 [2] c5 b8 [2] c7 b9 [2] dc bf [2] c0 b8 [2] dc 97 }

  condition:
    any of them
}