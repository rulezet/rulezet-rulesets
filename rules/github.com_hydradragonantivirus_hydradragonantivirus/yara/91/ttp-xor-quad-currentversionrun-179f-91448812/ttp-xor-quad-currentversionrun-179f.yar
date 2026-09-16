rule TTP_XOR_QUAD_CurrentVersionRun_179f {
  strings:
    $key_179f = { 44 f0 [2] 60 fe [2] 4b d2 [2] 65 f0 [2] 71 eb [2] 7e f1 [2] 60 ec [2] 62 ed [2] 79 eb [2] 65 ec [2] 79 c3 }

  condition:
    any of them
}