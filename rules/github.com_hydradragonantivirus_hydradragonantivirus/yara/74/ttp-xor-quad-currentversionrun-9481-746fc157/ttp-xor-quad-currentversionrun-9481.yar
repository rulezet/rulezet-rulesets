rule TTP_XOR_QUAD_CurrentVersionRun_9481 {
  strings:
    $key_9481 = { c7 ee [2] e3 e0 [2] c8 cc [2] e6 ee [2] f2 f5 [2] fd ef [2] e3 f2 [2] e1 f3 [2] fa f5 [2] e6 f2 [2] fa dd }

  condition:
    any of them
}