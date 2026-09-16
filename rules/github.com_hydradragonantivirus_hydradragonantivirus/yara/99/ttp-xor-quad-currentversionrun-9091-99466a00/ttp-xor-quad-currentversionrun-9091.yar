rule TTP_XOR_QUAD_CurrentVersionRun_9091 {
  strings:
    $key_9091 = { c3 fe [2] e7 f0 [2] cc dc [2] e2 fe [2] f6 e5 [2] f9 ff [2] e7 e2 [2] e5 e3 [2] fe e5 [2] e2 e2 [2] fe cd }

  condition:
    any of them
}