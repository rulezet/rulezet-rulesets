rule TTP_XOR_QUAD_CurrentVersionRun_928d {
  strings:
    $key_928d = { c1 e2 [2] e5 ec [2] ce c0 [2] e0 e2 [2] f4 f9 [2] fb e3 [2] e5 fe [2] e7 ff [2] fc f9 [2] e0 fe [2] fc d1 }

  condition:
    any of them
}