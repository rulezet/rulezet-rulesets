rule TTP_XOR_QUAD_CurrentVersionRun_90ee {
  strings:
    $key_90ee = { c3 81 [2] e7 8f [2] cc a3 [2] e2 81 [2] f6 9a [2] f9 80 [2] e7 9d [2] e5 9c [2] fe 9a [2] e2 9d [2] fe b2 }

  condition:
    any of them
}