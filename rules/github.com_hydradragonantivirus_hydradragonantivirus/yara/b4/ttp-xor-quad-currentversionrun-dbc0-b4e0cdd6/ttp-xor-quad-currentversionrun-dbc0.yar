rule TTP_XOR_QUAD_CurrentVersionRun_dbc0 {
  strings:
    $key_dbc0 = { 88 af [2] ac a1 [2] 87 8d [2] a9 af [2] bd b4 [2] b2 ae [2] ac b3 [2] ae b2 [2] b5 b4 [2] a9 b3 [2] b5 9c }

  condition:
    any of them
}