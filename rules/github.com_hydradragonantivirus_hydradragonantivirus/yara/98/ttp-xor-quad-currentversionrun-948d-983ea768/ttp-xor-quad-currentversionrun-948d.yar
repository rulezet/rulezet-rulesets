rule TTP_XOR_QUAD_CurrentVersionRun_948d {
  strings:
    $key_948d = { c7 e2 [2] e3 ec [2] c8 c0 [2] e6 e2 [2] f2 f9 [2] fd e3 [2] e3 fe [2] e1 ff [2] fa f9 [2] e6 fe [2] fa d1 }

  condition:
    any of them
}