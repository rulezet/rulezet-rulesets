rule TTP_XOR_QUAD_CurrentVersionRun_9090 {
  strings:
    $key_9090 = { c3 ff [2] e7 f1 [2] cc dd [2] e2 ff [2] f6 e4 [2] f9 fe [2] e7 e3 [2] e5 e2 [2] fe e4 [2] e2 e3 [2] fe cc }

  condition:
    any of them
}