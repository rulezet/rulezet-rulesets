rule TTP_XOR_QUAD_CurrentVersionRun_0d9f {
  strings:
    $key_0d9f = { 5e f0 [2] 7a fe [2] 51 d2 [2] 7f f0 [2] 6b eb [2] 64 f1 [2] 7a ec [2] 78 ed [2] 63 eb [2] 7f ec [2] 63 c3 }

  condition:
    any of them
}