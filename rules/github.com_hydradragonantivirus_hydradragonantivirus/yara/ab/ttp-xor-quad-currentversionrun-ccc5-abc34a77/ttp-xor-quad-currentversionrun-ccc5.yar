rule TTP_XOR_QUAD_CurrentVersionRun_ccc5 {
  strings:
    $key_ccc5 = { 9f aa [2] bb a4 [2] 90 88 [2] be aa [2] aa b1 [2] a5 ab [2] bb b6 [2] b9 b7 [2] a2 b1 [2] be b6 [2] a2 99 }

  condition:
    any of them
}