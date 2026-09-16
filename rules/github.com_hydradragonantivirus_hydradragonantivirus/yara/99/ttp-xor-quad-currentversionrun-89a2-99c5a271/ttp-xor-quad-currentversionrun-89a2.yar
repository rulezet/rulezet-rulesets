rule TTP_XOR_QUAD_CurrentVersionRun_89a2 {
  strings:
    $key_89a2 = { da cd [2] fe c3 [2] d5 ef [2] fb cd [2] ef d6 [2] e0 cc [2] fe d1 [2] fc d0 [2] e7 d6 [2] fb d1 [2] e7 fe }

  condition:
    any of them
}