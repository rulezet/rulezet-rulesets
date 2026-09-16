rule TTP_XOR_QUAD_CurrentVersionRun_ccbe {
  strings:
    $key_ccbe = { 9f d1 [2] bb df [2] 90 f3 [2] be d1 [2] aa ca [2] a5 d0 [2] bb cd [2] b9 cc [2] a2 ca [2] be cd [2] a2 e2 }

  condition:
    any of them
}