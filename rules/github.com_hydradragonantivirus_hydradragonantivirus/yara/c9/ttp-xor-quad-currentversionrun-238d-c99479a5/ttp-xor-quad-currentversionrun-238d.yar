rule TTP_XOR_QUAD_CurrentVersionRun_238d {
  strings:
    $key_238d = { 70 e2 [2] 54 ec [2] 7f c0 [2] 51 e2 [2] 45 f9 [2] 4a e3 [2] 54 fe [2] 56 ff [2] 4d f9 [2] 51 fe [2] 4d d1 }

  condition:
    any of them
}