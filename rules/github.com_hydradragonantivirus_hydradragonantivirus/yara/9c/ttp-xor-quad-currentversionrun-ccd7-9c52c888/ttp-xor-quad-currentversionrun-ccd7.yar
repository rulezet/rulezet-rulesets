rule TTP_XOR_QUAD_CurrentVersionRun_ccd7 {
  strings:
    $key_ccd7 = { 9f b8 [2] bb b6 [2] 90 9a [2] be b8 [2] aa a3 [2] a5 b9 [2] bb a4 [2] b9 a5 [2] a2 a3 [2] be a4 [2] a2 8b }

  condition:
    any of them
}