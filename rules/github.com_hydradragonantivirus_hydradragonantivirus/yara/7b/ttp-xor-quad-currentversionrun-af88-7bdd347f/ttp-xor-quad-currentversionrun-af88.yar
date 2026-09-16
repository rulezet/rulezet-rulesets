rule TTP_XOR_QUAD_CurrentVersionRun_af88 {
  strings:
    $key_af88 = { fc e7 [2] d8 e9 [2] f3 c5 [2] dd e7 [2] c9 fc [2] c6 e6 [2] d8 fb [2] da fa [2] c1 fc [2] dd fb [2] c1 d4 }

  condition:
    any of them
}