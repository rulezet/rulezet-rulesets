rule TTP_XOR_QUAD_CurrentVersionRun_d029 {
  strings:
    $key_d029 = { 83 46 [2] a7 48 [2] 8c 64 [2] a2 46 [2] b6 5d [2] b9 47 [2] a7 5a [2] a5 5b [2] be 5d [2] a2 5a [2] be 75 }

  condition:
    any of them
}