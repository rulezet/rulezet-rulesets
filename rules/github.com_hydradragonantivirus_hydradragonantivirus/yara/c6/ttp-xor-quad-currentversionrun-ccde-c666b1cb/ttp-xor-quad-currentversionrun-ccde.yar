rule TTP_XOR_QUAD_CurrentVersionRun_ccde {
  strings:
    $key_ccde = { 9f b1 [2] bb bf [2] 90 93 [2] be b1 [2] aa aa [2] a5 b0 [2] bb ad [2] b9 ac [2] a2 aa [2] be ad [2] a2 82 }

  condition:
    any of them
}