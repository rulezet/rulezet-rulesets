rule TTP_XOR_QUAD_CurrentVersionRun_dca2 {
  strings:
    $key_dca2 = { 8f cd [2] ab c3 [2] 80 ef [2] ae cd [2] ba d6 [2] b5 cc [2] ab d1 [2] a9 d0 [2] b2 d6 [2] ae d1 [2] b2 fe }

  condition:
    any of them
}