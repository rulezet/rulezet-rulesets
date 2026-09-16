rule TTP_XOR_QUAD_CurrentVersionRun_06be {
  strings:
    $key_06be = { 55 d1 [2] 71 df [2] 5a f3 [2] 74 d1 [2] 60 ca [2] 6f d0 [2] 71 cd [2] 73 cc [2] 68 ca [2] 74 cd [2] 68 e2 }

  condition:
    any of them
}