rule TTP_XOR_QUAD_CurrentVersionRun_049f {
  strings:
    $key_049f = { 57 f0 [2] 73 fe [2] 58 d2 [2] 76 f0 [2] 62 eb [2] 6d f1 [2] 73 ec [2] 71 ed [2] 6a eb [2] 76 ec [2] 6a c3 }

  condition:
    any of them
}