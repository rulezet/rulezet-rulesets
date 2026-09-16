rule TTP_XOR_QUAD_CurrentVersionRun_cc9d {
  strings:
    $key_cc9d = { 9f f2 [2] bb fc [2] 90 d0 [2] be f2 [2] aa e9 [2] a5 f3 [2] bb ee [2] b9 ef [2] a2 e9 [2] be ee [2] a2 c1 }

  condition:
    any of them
}