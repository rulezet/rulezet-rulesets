rule TTP_XOR_QUAD_CurrentVersionRun_b9cd {
  strings:
    $key_b9cd = { ea a2 [2] ce ac [2] e5 80 [2] cb a2 [2] df b9 [2] d0 a3 [2] ce be [2] cc bf [2] d7 b9 [2] cb be [2] d7 91 }

  condition:
    any of them
}