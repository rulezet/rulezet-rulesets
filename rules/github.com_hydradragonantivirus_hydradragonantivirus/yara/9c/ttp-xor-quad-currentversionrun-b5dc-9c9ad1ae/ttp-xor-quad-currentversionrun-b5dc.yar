rule TTP_XOR_QUAD_CurrentVersionRun_b5dc {
  strings:
    $key_b5dc = { e6 b3 [2] c2 bd [2] e9 91 [2] c7 b3 [2] d3 a8 [2] dc b2 [2] c2 af [2] c0 ae [2] db a8 [2] c7 af [2] db 80 }

  condition:
    any of them
}