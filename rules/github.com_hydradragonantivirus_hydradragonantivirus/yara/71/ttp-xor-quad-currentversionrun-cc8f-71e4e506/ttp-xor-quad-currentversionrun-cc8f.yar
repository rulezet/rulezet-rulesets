rule TTP_XOR_QUAD_CurrentVersionRun_cc8f {
  strings:
    $key_cc8f = { 9f e0 [2] bb ee [2] 90 c2 [2] be e0 [2] aa fb [2] a5 e1 [2] bb fc [2] b9 fd [2] a2 fb [2] be fc [2] a2 d3 }

  condition:
    any of them
}