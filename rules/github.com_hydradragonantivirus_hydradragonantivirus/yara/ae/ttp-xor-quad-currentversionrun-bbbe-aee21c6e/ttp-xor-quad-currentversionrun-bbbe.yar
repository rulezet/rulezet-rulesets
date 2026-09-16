rule TTP_XOR_QUAD_CurrentVersionRun_bbbe {
  strings:
    $key_bbbe = { e8 d1 [2] cc df [2] e7 f3 [2] c9 d1 [2] dd ca [2] d2 d0 [2] cc cd [2] ce cc [2] d5 ca [2] c9 cd [2] d5 e2 }

  condition:
    any of them
}