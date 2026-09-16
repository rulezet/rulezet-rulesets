rule TTP_XOR_QUAD_CurrentVersionRun_3d9f {
  strings:
    $key_3d9f = { 6e f0 [2] 4a fe [2] 61 d2 [2] 4f f0 [2] 5b eb [2] 54 f1 [2] 4a ec [2] 48 ed [2] 53 eb [2] 4f ec [2] 53 c3 }

  condition:
    any of them
}