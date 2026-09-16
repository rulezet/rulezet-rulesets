rule TTP_XOR_QUAD_CurrentVersionRun_33ab {
  strings:
    $key_33ab = { 60 c4 [2] 44 ca [2] 6f e6 [2] 41 c4 [2] 55 df [2] 5a c5 [2] 44 d8 [2] 46 d9 [2] 5d df [2] 41 d8 [2] 5d f7 }

  condition:
    any of them
}