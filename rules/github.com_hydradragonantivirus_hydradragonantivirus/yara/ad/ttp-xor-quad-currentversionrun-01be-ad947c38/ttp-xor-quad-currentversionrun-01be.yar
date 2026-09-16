rule TTP_XOR_QUAD_CurrentVersionRun_01be {
  strings:
    $key_01be = { 52 d1 [2] 76 df [2] 5d f3 [2] 73 d1 [2] 67 ca [2] 68 d0 [2] 76 cd [2] 74 cc [2] 6f ca [2] 73 cd [2] 6f e2 }

  condition:
    any of them
}