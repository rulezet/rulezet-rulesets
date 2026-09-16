rule TTP_XOR_QUAD_CurrentVersionRun_069f {
  strings:
    $key_069f = { 55 f0 [2] 71 fe [2] 5a d2 [2] 74 f0 [2] 60 eb [2] 6f f1 [2] 71 ec [2] 73 ed [2] 68 eb [2] 74 ec [2] 68 c3 }

  condition:
    any of them
}