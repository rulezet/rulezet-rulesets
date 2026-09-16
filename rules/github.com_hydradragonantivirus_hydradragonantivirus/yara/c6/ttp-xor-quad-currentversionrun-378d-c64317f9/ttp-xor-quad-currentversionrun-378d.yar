rule TTP_XOR_QUAD_CurrentVersionRun_378d {
  strings:
    $key_378d = { 64 e2 [2] 40 ec [2] 6b c0 [2] 45 e2 [2] 51 f9 [2] 5e e3 [2] 40 fe [2] 42 ff [2] 59 f9 [2] 45 fe [2] 59 d1 }

  condition:
    any of them
}