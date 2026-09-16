rule TTP_XOR_QUAD_CurrentVersionRun_8ba3 {
  strings:
    $key_8ba3 = { d8 cc [2] fc c2 [2] d7 ee [2] f9 cc [2] ed d7 [2] e2 cd [2] fc d0 [2] fe d1 [2] e5 d7 [2] f9 d0 [2] e5 ff }

  condition:
    any of them
}