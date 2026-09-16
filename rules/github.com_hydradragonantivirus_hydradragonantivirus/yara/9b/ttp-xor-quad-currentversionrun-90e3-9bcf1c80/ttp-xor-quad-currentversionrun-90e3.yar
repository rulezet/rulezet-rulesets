rule TTP_XOR_QUAD_CurrentVersionRun_90e3 {
  strings:
    $key_90e3 = { c3 8c [2] e7 82 [2] cc ae [2] e2 8c [2] f6 97 [2] f9 8d [2] e7 90 [2] e5 91 [2] fe 97 [2] e2 90 [2] fe bf }

  condition:
    any of them
}