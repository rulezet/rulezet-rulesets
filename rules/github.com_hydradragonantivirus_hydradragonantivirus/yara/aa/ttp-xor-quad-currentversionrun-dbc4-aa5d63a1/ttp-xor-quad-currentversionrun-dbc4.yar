rule TTP_XOR_QUAD_CurrentVersionRun_dbc4 {
  strings:
    $key_dbc4 = { 88 ab [2] ac a5 [2] 87 89 [2] a9 ab [2] bd b0 [2] b2 aa [2] ac b7 [2] ae b6 [2] b5 b0 [2] a9 b7 [2] b5 98 }

  condition:
    any of them
}