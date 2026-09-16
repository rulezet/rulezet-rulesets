rule TTP_XOR_QUAD_CurrentVersionRun_a6be {
  strings:
    $key_a6be = { f5 d1 [2] d1 df [2] fa f3 [2] d4 d1 [2] c0 ca [2] cf d0 [2] d1 cd [2] d3 cc [2] c8 ca [2] d4 cd [2] c8 e2 }

  condition:
    any of them
}