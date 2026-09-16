rule TTP_XOR_QUAD_CurrentVersionRun_948f {
  strings:
    $key_948f = { c7 e0 [2] e3 ee [2] c8 c2 [2] e6 e0 [2] f2 fb [2] fd e1 [2] e3 fc [2] e1 fd [2] fa fb [2] e6 fc [2] fa d3 }

  condition:
    any of them
}